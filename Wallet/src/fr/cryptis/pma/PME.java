package fr.cryptis.pma;


import javacard.framework.*;
import javacard.security.*;

/**
 *
 * Class PME
 * @author Rokia 
 * Cette classe implémente les méthodes traitant les APDU envoyées par un une application bancaire (le host)
 */
public class PME extends Applet{
	
	/**
	 * La valeur possible de l'octet de CLA
	 */
	public final static byte PMA_CLA = (byte)0xB0;

	/**
	 * Les valeurs possibles de l'octet de INS
	 */
	public final static byte USR_GET_BALANCE = (byte)0x50;
	public final static byte USR_VERIFY = (byte)0x20;
	public final static byte USR_CREDIT = (byte)0x30;
	public final static byte USR_DEBIT = (byte)0x40;
	public final static byte ADM_INIT = (byte)0x90;
	public final static byte ADM_GET_PUBLIC_KEY = (byte)0x80;
	public final static byte ADM_GET_LOG = (byte)0x70;
	public final static byte ADM_VERIFY = (byte)0x60;
	
	/**
	 * Les valeurs possibles de l'octet de P1
	 */
	public final static byte ADM_FIX_BALANCE_AMOUNT = (byte)0x01;
	public final static byte ADM_INIT_USR_PIN = (byte)0x02;
	public final static byte ADM_UNBLOCK_USR_PIN = (byte)0x03;
	
	/**
	 * les paramètres de PIN
	 */
	public final static byte MAX_PIN_SIZE = (byte)0x08;
	public final static byte USR_PIN_TRY_LIMIT = (byte)0x03;
	public final static byte ADMIN_PIN_TRY_LIMIT = (byte)0x01;
	
	/**
	 * Les valeurs maximales que peuvent prendre la balance et le montant
	 */
	private final static short MAX_INTEGER_PART_BALANCE = (short)0xFFFF;
	private final static byte MAX_DECIMAL_PART_BALANCE = (byte)0x63;
	private final static byte MAX_INTEGER_PART_AMOUNT = (byte)0xFF;
	private final static byte MAX_DECIMAL_PART_AMOUNT = (byte)0x63;
	
	
	/**
	 * status words 
	 */
	public final static short SW_VERIFICATION_FAILED = (short)0x63C0;
	public final static short SW_PIN_BLOCKED = (short)0x6300;
	public final static short SW_VERIFICATION_REQUIRED = (short)0x6301;
	public final static short SW_INVALID_TRANSACTION_AMOUNT = (short)0x6A83;
	public final static short SW_EXCEED_MAXIMUM_BALANCE = (short)0x6A84;
	public final static short SW_NEGATIVE_BALANCE = (short)0x6A85;
	public final static short SW_ADMINISTRATION_REQUIRED = (short)0x6A86;
	private static final short SW_INVALID_TRANSACTION_BALANCE = (short)0x6A89;
	
	/**
	 * Les éléments cryptographiques 
	 */
	private final static short RSA_KEY_BITS_SIZE = (short) 512; //taille de la clé RSA (en bits)
	private final static byte  RSA_KEY_BYTES_MAX_SIZE = (byte)0x40;//taille de la clé RSA(en octet)
	private final static byte  DATA_TO_SIGN_LENGHT = (byte)0x08; //taille de données qu'on va signer (en octet)
	private final static byte  MAX_SIGNED_DATA_LENGHT = (byte)0x40; //taille maximale de la signature
	
	/**
	 * La valeur maximal de l'index dans le fichier de logs
	 */
	private final static byte  MAX_RECORDS_NUMBER= (byte)0x09;

	
	
	/**
	 * La déclaration des variables d'instance
	 */
	private short integer_part_balance;
	private byte  decimal_part_balance;
	
	private byte  integer_part_amount;
	private byte  decimal_part_amount;
	
	private OwnerPIN pin_admin;
	private OwnerPIN pin_user;
	
	private KeyPair rsakeypair;
	private RSAPublicKey rsapublickey;
	private byte[] modulus;
	private byte[] exponent;
	
	private Signature s;
	private byte[] data_to_sign;
	private byte[] signed_data;
	
	private boolean adm_init; //le user ne peut envoyer aucune commande si adm_init=false 
	
	private RecordBankingOperation rbo;
	
	/**
	 * Constructeur de la classe
	 * @param bArray le tableau qui contient le PIN de l'admin
	 * @param bOffset l'offset où commence les données de l'Applet
	 * @param bLenght la longueur du tableau
	 */
	public PME(byte[] bArray,short bOffset,byte bLenght) {
		
		adm_init = false;
		
		integer_part_balance = (short)100; //initialisation de la partie entière de balance
		decimal_part_balance = (byte)00; //initialisation de la partie décimale de balance
		
		pin_user = new OwnerPIN(USR_PIN_TRY_LIMIT,MAX_PIN_SIZE);
		
		// Les paramètres de l'intsallation contiennent le PIN de l'admin
		pin_admin = new OwnerPIN(ADMIN_PIN_TRY_LIMIT,MAX_PIN_SIZE);
		byte iLen = bArray[bOffset]; // La longueur de l'AID
		bOffset = (short) (bOffset+iLen+1);
		byte cLen = bArray[bOffset]; 
		bOffset = (short) (bOffset+cLen+1);
		byte aLen = bArray[bOffset]; // La longueur du PIN
		// initialisation du PIN de l'admin
		pin_admin.update(bArray, (short)(bOffset+1), aLen);
	
		//création de la paire de clé RSA
		rsakeypair = new KeyPair(KeyPair.ALG_RSA_CRT,RSA_KEY_BITS_SIZE);
		rsakeypair.genKeyPair();
		rsapublickey = (RSAPublicKey) rsakeypair.getPublic();
		modulus = new byte[RSA_KEY_BYTES_MAX_SIZE];
		exponent = new byte[RSA_KEY_BYTES_MAX_SIZE];
		
		//instanciation de l'objet Signature et choix de l'algorithme de signature et de hachage
		s = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false);
		
		data_to_sign = new byte[DATA_TO_SIGN_LENGHT];
		signed_data = new byte[MAX_SIGNED_DATA_LENGHT];
		
		//instanciation de la classe qui gère l'enregistrement des opérations bancaires
		rbo = new RecordBankingOperation();
		
		//enregistrement de l'applet auprès du JCRE
		register();
		
	}

	/**
	 * Installation de l'applet 
	 * @param bArray contient l'AID, le PIN de l'admin et d'autres informations
	 * @param bOffset
	 * @param bLength
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength){
		new PME(bArray, bOffset, bLength);
	}
	
	/**
	 * Traitement des commandes APDU envoyées par le host
	 */
	public void process(APDU apdu){
		
		byte[] buf = apdu.getBuffer();
		
		if(selectingApplet())
			{
				return;
			}
		if(buf[ISO7816.OFFSET_CLA]!= PMA_CLA)
			{
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			}
		switch(buf[ISO7816.OFFSET_INS]){
			case (byte)USR_GET_BALANCE:
				usr_get_balance(apdu);
				break;
			case (byte)USR_VERIFY:
				usr_verify(apdu);
				break;
			case (byte)USR_CREDIT:
				usr_credit(apdu);
				break;
			case (byte)USR_DEBIT:
				usr_debit(apdu);
				break;
			case (byte)ADM_INIT:
				adm_init(apdu);
				break;
			case (byte)ADM_GET_PUBLIC_KEY:
				adm_get_public_key(apdu);
				break; 
			case (byte)ADM_GET_LOG:
				adm_get_log(apdu);
				break;
			case (byte)ADM_VERIFY:
				adm_verify(apdu);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	/**
	 * Vérification de la valeur du PIN de l'admin
	 * @param apdu
	 */
	private void adm_verify(APDU apdu) {
		
		if(pin_admin.getTriesRemaining()==0)
		{
			//pin bloqué, car le nombre d'essais possibles est égale à 1
			ISOException.throwIt(SW_PIN_BLOCKED);
		}
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		if(bytesRead > MAX_PIN_SIZE && buffer[ISO7816.OFFSET_LC] > MAX_PIN_SIZE)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		if (pin_admin.check(buffer,(short)ISO7816.OFFSET_CDATA,(byte)bytesRead) == false)
		{
			//échec de vérification de PIN et blocage de PIN
			ISOException.throwIt(SW_PIN_BLOCKED);
		}
	}

	/**
	 * Lire un enregistrement dans le fichier de logs
	 * @param apdu
	 */
	private void adm_get_log(APDU apdu) {
		
		if(! pin_admin.isValidated())
		{
			//on ne peut utiliser cette méthode que si la vérification de PIN était réussie
			ISOException.throwIt(SW_VERIFICATION_REQUIRED);
		}
		
		byte[] buffer = apdu.getBuffer();
		//Le numéro d'enregistrement qu'on souhaite lire est donné par buffer[ISO7816.OFFSET_P1]
		if(buffer[ISO7816.OFFSET_P1] > MAX_RECORDS_NUMBER )
		{
			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
		}
		rbo.getLog(buffer[ISO7816.OFFSET_P1], buffer, (short)0);
		apdu.setOutgoingAndSend((short)0, (short)(DATA_TO_SIGN_LENGHT+MAX_SIGNED_DATA_LENGHT));
	}

	/**
	 * Récupérer la clé publique RSA: module et exposant
	 * @param apdu
	 */
	private void adm_get_public_key(APDU apdu) {
		
			if(! pin_admin.isValidated())
			{
				//on ne peut utiliser cette méthode que si la vérification de PIN était réussie
				ISOException.throwIt(SW_VERIFICATION_REQUIRED);
			}
			
			byte[] buffer = apdu.getBuffer();
		    if(buffer[ISO7816.OFFSET_LC]!= RSA_KEY_BYTES_MAX_SIZE)
			{
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
		    
		    short moduluslenght = rsapublickey.getModulus(modulus,(short)0);
		    short exponentlenght = rsapublickey.getExponent(exponent,(short)0);
		    
		    //envoyer la clé publique : module + exposant
		    apdu.setOutgoing();
		    apdu.setOutgoingLength((short)(moduluslenght + exponentlenght));
		    apdu.sendBytesLong(modulus, (short)0, moduluslenght);
		    apdu.sendBytesLong(exponent, (short)0, exponentlenght);
}

	/**
	 * Initialiser le PIN de l'utilisateur & Fixer la valeur de la balance & débloquer le PIN de l'utilisateur
	 * @param apdu
	 */
	private void adm_init(APDU apdu) {
		
		if(! pin_admin.isValidated())
		{
			//on ne peut utiliser cette méthode que si la vérification de PIN était réussie
			ISOException.throwIt(SW_VERIFICATION_REQUIRED);
		}

		short bytesread = 0;
		
		//récuperer le buffer APDU
	    byte[] buffer = apdu.getBuffer();
	    
		switch(buffer[ISO7816.OFFSET_P1])
		{
				case ADM_FIX_BALANCE_AMOUNT:
					//fixer la balance à une valeur donnée dans le APDU
					
					if(buffer[ISO7816.OFFSET_LC]!=(byte)0x03)
					{
						ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					}
					bytesread = apdu.setIncomingAndReceive();
					JCSystem.beginTransaction();
					integer_part_balance = (short)((buffer[ISO7816.OFFSET_CDATA] << (short)8) | (((short)buffer[ISO7816.OFFSET_CDATA + 1]) & (short)0x00FF));
					decimal_part_balance = (byte) buffer[ISO7816.OFFSET_CDATA +2];
					
					if((short)(decimal_part_balance & 0x00FF) > (short)MAX_DECIMAL_PART_BALANCE)
					{
						//le maximum de balance est dépassé 
						JCSystem.abortTransaction();
						ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
					}
		
					JCSystem.commitTransaction();
					break;
				case ADM_INIT_USR_PIN:
					//initialiser le pin de l'utilisateur
					
					 if(buffer[ISO7816.OFFSET_LC] > MAX_PIN_SIZE)
					 {
						ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
					 }
					 //on change la valeur de adm_init à true pour que l'utilisateur puisse utiliser les autres opérations
					 adm_init = true;
					 bytesread = apdu.setIncomingAndReceive();
					 pin_user.update(buffer,(short)(ISO7816.OFFSET_CDATA),(byte)bytesread);
					 break;
				  case ADM_UNBLOCK_USR_PIN:
					  //débloquer le PIN de l'utilisateur
					  
					  if(pin_user.getTriesRemaining()==0)
					  {
						  pin_user.resetAndUnblock();
					  }
					  break;
				  default:
				  	ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			  }
		
	}

	/**
	 * Débiter la balance
	 * @param apdu
	 */
	private void usr_debit(APDU apdu) {
		
		if(! pin_user.isValidated())
		{
			//on ne peut utiliser cette méthode que si la vérification de PIN était réussie
			ISOException.throwIt(SW_VERIFICATION_REQUIRED);
		}

		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		if(buffer[ISO7816.OFFSET_LC]!=2 || bytesRead !=2)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		decimal_part_amount = buffer[ISO7816.OFFSET_CDATA +1];
		integer_part_amount = buffer[ISO7816.OFFSET_CDATA];
		//on convertit le montant à sa valeur positive car le montant est supposé avoir les valeur entre 0 et 255
		short converted_integer_part_amount = (short) (((short)integer_part_amount) & 0x00FF);
		
		//montant = 0x00C2 par exemple, n'est pas valide car 0x00C2 > 0x0063
		if((short)(decimal_part_amount & 0x00FF) > (short)MAX_DECIMAL_PART_AMOUNT)
		{
			//montant invalide
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}
		
		byte LSB = (byte) integer_part_balance;
		byte MSB = (byte) (integer_part_balance >> 8);
		//comparer balance et montant
		if( MSB == (byte)0)
		{
			if(((short) ((short)LSB & 0x00FF)) <  converted_integer_part_amount)
			{
				//la balance est négative
				ISOException.throwIt(SW_NEGATIVE_BALANCE);
			}
		}
		
		//comparer balance et montant
		if(((converted_integer_part_amount == integer_part_balance) && (decimal_part_amount>decimal_part_balance)))
		{
			//la balance est négative
			ISOException.throwIt(SW_NEGATIVE_BALANCE);
		}
		
		//mettre les données à signer dans le tableau data_to_sign
		data_to_sign[0] = (byte)(integer_part_balance >> 8);
		data_to_sign[1] = (byte)(integer_part_balance);
		data_to_sign[2] = decimal_part_balance;
		data_to_sign[3] = integer_part_amount;
		data_to_sign[4] = decimal_part_amount;
		
		//commencer l'opération de débit
		
		//on traite en premier la partie décimale 
		short retenue = 0;
		if(decimal_part_amount > decimal_part_balance)
		{
			decimal_part_balance += ((MAX_DECIMAL_PART_BALANCE+1) - decimal_part_amount);
			retenue = 1;
		}
		else if(decimal_part_amount <= decimal_part_balance)
		{
			decimal_part_balance -= decimal_part_amount;
		}
		
		//et ensuite la partie entière
		integer_part_balance -= (converted_integer_part_amount + retenue);
		
		//on met aussi la nouvelle valeur de balance dans le tableau des données à signer
		data_to_sign[5] = (byte)(integer_part_balance >> 8);
		data_to_sign[6] = (byte)(integer_part_balance);
		data_to_sign[7] = decimal_part_balance;
		
		//on signe
		s.init((RSAPrivateCrtKey)rsakeypair.getPrivate(),Signature.MODE_SIGN);
		s.update(data_to_sign,(short)0, (short)DATA_TO_SIGN_LENGHT);
		short signed_data_lenght = s.sign(data_to_sign,(short)0,(short)DATA_TO_SIGN_LENGHT,signed_data,(short)0);
		
		//on enregistre l'opération de débit dans le fichier de logs
		rbo.writeLog(data_to_sign, signed_data);
		
		//on envoie la signature de l'opération 
		apdu.setOutgoing();
		apdu.setOutgoingLength(signed_data_lenght);
		apdu.sendBytesLong(signed_data, (short)0, signed_data_lenght);
  }
		

	/**
	 * Créditer la balance
	 * @param apdu
	 */
	private void usr_credit(APDU apdu) {
		
		
		if(! pin_user.isValidated())
		{
			//on ne peut utiliser cette méthode que si la vérification de PIN était réussie
			ISOException.throwIt(SW_VERIFICATION_REQUIRED);
		}

		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		if(buffer[ISO7816.OFFSET_LC]!=2 || bytesRead !=2)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		decimal_part_amount = buffer[ISO7816.OFFSET_CDATA +1];
		integer_part_amount = buffer[ISO7816.OFFSET_CDATA];
		
		// 0x00FF par exemple, n'est pas possible car 0xFF > 0x64
		if((short)(((short)decimal_part_amount) & 0x00FF) > (short)MAX_DECIMAL_PART_AMOUNT)
		{
			//montant invalide
			ISOException.throwIt(SW_INVALID_TRANSACTION_AMOUNT);
		}
		
		//on convertit le montant à sa valeur positive car le montant est supposé avoir les valeur entre 0 et 255
		short converted_integer_part_amount = (short) (((short) integer_part_amount) & 0x00FF);
		
		//0xFFFFyy + 0xzztt avec zz#0 n'est pas possible
		if((integer_part_balance == MAX_INTEGER_PART_BALANCE) && converted_integer_part_amount != (short)0)
		{
			//le maximum de balance est dépassé 
			ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
		}
		
		//on calcule la somme du montant et balance
		byte decimal_parts_sum = (byte)(decimal_part_amount + decimal_part_balance);
		short integer_parts_sum = (short)(converted_integer_part_amount + integer_part_balance);
		
	    //0xFFFFyy + 0xzztt avec yy + tt > 0x63 n'est pas possible car il y aura une retenue
		if((integer_part_balance == MAX_INTEGER_PART_BALANCE) && ((short)(decimal_parts_sum &0x00FF) > (short)MAX_DECIMAL_PART_BALANCE))
		{
			//le maximum de balance est dépassé
			ISOException.throwIt(SW_EXCEED_MAXIMUM_BALANCE);
		}
						
		//mettre les données à signer dans le tableau data_to_sign
		data_to_sign[0] = (byte)(integer_part_balance >> 8);
		data_to_sign[1] = (byte)(integer_part_balance);
		data_to_sign[2] = decimal_part_balance;
		data_to_sign[3] = integer_part_amount;
		data_to_sign[4] = decimal_part_amount;
		
		//commencer l'opération de crédit
		
		//on traite en premier la partie décimale
		short retenue = 0;
		if(((short)(decimal_parts_sum &0x00FF)) > (short)MAX_DECIMAL_PART_BALANCE)
		{
			//retrancher 0x63 + 1 = 0x64 = (100 en base 10)
			decimal_part_balance = (byte) (decimal_parts_sum - (MAX_DECIMAL_PART_BALANCE+1));
			retenue = 1;
		}
		else
		{
			decimal_part_balance = decimal_parts_sum;
		}
		
		//et ensuite la partie entière
	    integer_part_balance = (short) (integer_parts_sum + retenue) ;
	    
		//on met également la nouvelle valeur de balance dans le tableau des données à signer
		data_to_sign[5] = (byte)(integer_part_balance >> 8);
		data_to_sign[6] = (byte)(integer_part_balance);
		data_to_sign[7] = decimal_part_balance;
		
		//signer
	    s.init((RSAPrivateCrtKey)rsakeypair.getPrivate(),Signature.MODE_SIGN);
		s.update(data_to_sign,(short)0, (short)DATA_TO_SIGN_LENGHT);
		short signed_data_lenght = s.sign(data_to_sign,(short)0,(short)DATA_TO_SIGN_LENGHT,signed_data,(short)0);
		
		//enregistrer l'opération de crédit dans le fichier de logs
		rbo.writeLog(data_to_sign, signed_data);
		
		//envoyer la signature
		apdu.setOutgoing();
		apdu.setOutgoingLength(signed_data_lenght);
		apdu.sendBytesLong(signed_data, (short)0, signed_data_lenght);
					
	}

	/**
	 * Vérification du PIN de l'utilisateur
	 * @param apdu
	 */
	private void usr_verify(APDU apdu) {
		
		if(!adm_init)
		{
			//on ne peut appeler cette méthode que si le PIN de l'utilisateur a été initialisé via l'appel à la méthode adm_init 
			ISOException.throwIt(SW_ADMINISTRATION_REQUIRED);
		}
		
		if(pin_user.getTriesRemaining()==0)
		{
			//pin blocked
			ISOException.throwIt(SW_PIN_BLOCKED);
		}
		
		byte[] buffer = apdu.getBuffer();
		short bytesRead = apdu.setIncomingAndReceive();
		
		if(bytesRead > MAX_PIN_SIZE && buffer[ISO7816.OFFSET_LC] > MAX_PIN_SIZE)
		{
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
		if (pin_user.check(buffer,(short)ISO7816.OFFSET_CDATA,(byte)bytesRead) == false)
		{
			//on renvoie l'exception 0x63Cy avec y est le nombre d'essais restant
			ISOException.throwIt((short)((SW_VERIFICATION_FAILED) | ((short)(pin_user.getTriesRemaining()))) ) ;
		}
		
	}
		

	/**
	 * Lire la valeur de balance
	 * @param apdu
	 */
	private void usr_get_balance(APDU apdu) {
		
		if(! pin_user.isValidated())
		{
			//on ne peut utiliser cette méthode que si la vérification de PIN était réussie
			ISOException.throwIt(SW_VERIFICATION_REQUIRED);
		}
		
		byte[] buffer = apdu.getBuffer();
		if(buffer[ISO7816.OFFSET_LC]!=(byte)0x03)
		{
			//Le n'est pas correct
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		buffer[0] = (byte) (integer_part_balance >> 8);
		buffer[1] = (byte) (integer_part_balance);
		buffer[2] = decimal_part_balance;
		apdu.setOutgoingAndSend((short)0,(short)3);
		
	}
	
	/**
	 * Déselection de l'applet
	 */
	public void deselect() {
		
		//à la déselection de l'applet, on demande à l'admin de présenter son PIN
		pin_admin.reset();
	}

	/**
	 * Sélection de l'applet
	 */
	public boolean select() {
		
		//L'applet refuse d'etre sélectionné si le nombre d'essais restant est égale à 0
		if(pin_admin.getTriesRemaining() == 0)
		{
			return false;
		}
		return true;
	}

}


package fr.cryptis.pma;

import javacard.framework.Util;

/**
 * Classe de gestion de journalisation des op�rations de d�bit 
 * et de cr�dit r�alis�es par l'utilisateur 
 * @author Rokia 
 *
 */
public class RecordBankingOperation {

	/**
	 * D�claraion des constantes 
	 */
	public static byte MAX_OPERATIONS_TO_SAVE = (byte)0x0A; //on ne peut pas enregistrer plus que 10 op�rations 
	public static short DATA_LENGHT = (short)0x08; // la longueur des donn�es (en octet)
	public static short MAX_SIGNATURE_LENGHT = (short)0x40; //la longueur de la signature (en octet)
	
	private static byte record_number = (byte)0x00;
	private static short record_index = (short)0x00;
	
	/**
	 * Le tableau contenant les informations sur les op�rations bancaires
	 */
	private byte[] logsArray;
	
	/**
	 * Constructeur de la classe
	 */
	public RecordBankingOperation() {
		
		logsArray = new byte[MAX_OPERATIONS_TO_SAVE*(DATA_LENGHT+MAX_SIGNATURE_LENGHT+1)];
	}
	
	/**
	 * Renvoie le contenu de l'enregistrement identifi� par le num�ro 'record'
	 * @param record num�ro de l'enregistrement
	 * @param buffer le tableau o� mettre le r�sultat
	 * @param offset offset de d�but dans le tableau 'buffer'
	 */
	public void getLog(short record,byte[] buffer,short offset)
	{
		// si record = 0, les donn�es sont � la position 1 du tableau
		// si record = 1, les donn�es sont � la position 73 du tableau, ..etc
		record =(short)( record + record *(DATA_LENGHT+MAX_SIGNATURE_LENGHT));
		//'record +1' car � la position 'record' , il y a le num�ro de l'enregistrement (0,1,2,..)
		Util.arrayCopyNonAtomic(logsArray,(short) (record+1), buffer, (short)0,(short)(DATA_LENGHT+MAX_SIGNATURE_LENGHT));
	}
	
	/**
	 * Ecrit les donn�es et la signature dans le tableau de Logs
	 * @param data les donn�es 
	 * @param signature la signature de ces donn�es
	 */
	public void writeLog(byte[] data, byte[] signature)
	{
		//quand on aura 10 enregistrements dans le tableau, on �crasera le premier pour �crire le nouveau
		if(record_number == MAX_OPERATIONS_TO_SAVE)
		{
			record_index = (short)0x00;
			record_number = (byte)0x00;
		}
		logsArray[record_index] = record_number;
		//on copie les donn�es dans le tableau logsArray
		Util.arrayCopyNonAtomic(data, (short)0, logsArray, (short)(record_index+1),(short) data.length);
		//on copie la signature dans le tableau logsArray
		Util.arrayCopyNonAtomic(signature, (short)0, logsArray, (short)(record_index+data.length+1),(short) signature.length);
		//on incr�mente le num�ro de l'enregistrement
		record_number ++;
		//on met � jour la valeur de record_index en prenant en consid�ration la longueur des donn�es d�j� �crites
		record_index = (short)(record_index + (DATA_LENGHT+MAX_SIGNATURE_LENGHT+1));
	}

}

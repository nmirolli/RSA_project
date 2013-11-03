//
// RSA Cryptography Program for Algorithms
// Created by Nicholas Mirolli Sept. 2013
// Copyright (c) 2013 Mirolli
//
// Implementation of RSA Cryptography including user choice from start of program.
// This version breaks the plaintext into blocks before encryption.
//

import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
import java.util.regex.Pattern;


public class RSA_Crypt {

	private BigInteger p, q; 	//Big integer prime numbers p and q
	private BigInteger n;		//Big integer n = p * q 
	private BigInteger phi_n;	//Big integer phi_n = (p-1)(q-1) 
	private BigInteger e, d;	//Big integers where e is relatively prime to phi_n, and d is the multiplicative inverse of e
	
	public RSA_Crypt(int choice) {
		Initialize(choice);			//Initializer for RSA objects
	}
	
	public void Initialize(int choice) {
	
		if(choice == 0) {
			int p_size, q_size, e_size;
			Scanner scanner_p = new Scanner (System.in);
			System.out.print("Enter the size (in digits) of p: ");
			p_size = scanner_p.nextInt();								//Takes in user input for size of p
			Scanner scanner_q = new Scanner (System.in);
			System.out.print("Enter the size (in digits) of q: ");
			q_size = scanner_q.nextInt();								//Takes in user input for size of q
			Scanner scanner_e = new Scanner (System.in);
			System.out.print("Enter the size (in digits) of e: ");
			e_size = scanner_e.nextInt();								//Takes in user input for size of e
			do {
				p = bigIntGen(p_size);									//Generates a random prime BigInteger "p" of the specified size
			} while (p.equals(BigInteger.valueOf(0)));
			System.out.print("p = " + p + "\n");						//Prints p
			do {
				q = bigIntGen(q_size);									//Generates a random prime BigInteger "q" of the specified size
			} while (q.equals(BigInteger.valueOf(0)));
			System.out.print("q = " + q + "\n");						//Prints q
			
			// Calculate n = p * q
			n = p.multiply(q);
			System.out.print("n = " + n + "\n");						//Prints n
			
			// Calculate phi_n = (p-1)(q-1)
			phi_n = p.subtract(BigInteger.valueOf(1));
			phi_n = phi_n.multiply(q.subtract(BigInteger.valueOf(1)));
			System.out.print("phi_n = " + phi_n + "\n");				//Prints phi_n
			
			// Calculate e, where e not equal to phi_n and is relatively prime to phi_n
			do {
				do {
					e = bigIntGen(e_size);								//Generates a random prime BigInteger "e" of the specified size
				} while (e.equals(BigInteger.valueOf(0)));
			}
			while ((e.compareTo(phi_n) == 0) || (e.gcd(phi_n).compareTo(BigInteger.valueOf(1)) != 0));
			//while (e.gcd(phi_n).compareTo(BigInteger.valueOf(1)) != 0);
			System.out.print("e = " + e + "\n");
			
			// Calculate d, where d is the multiplicative inverse of e
			d = e.modInverse(phi_n);
			System.out.print("d = " + d + "\n");
		}
		//Print values for debugging
		/*System.out.print("p = " + p + "\n");
		System.out.print("q = " + q + "\n");
		System.out.print("n = " + n + "\n");
		System.out.print("phi_n = " + phi_n + "\n");
		System.out.print("e = " + e + "\n");
		System.out.print("d = " + d + "\n");*/
	
	} //End of Initialize
	
	public static void main(String[] args) throws IOException { 
	
	int choice;
	Scanner scanner_c = new Scanner (System.in);
	System.out.print("What would you like to do? Enter 0 for Encryption or 1 for Decryption: ");
	choice = scanner_c.nextInt();
	//System.out.print("choice = \"" + choice + "\"\n");
	RSA_Crypt application = new RSA_Crypt(choice);													//Creates new object of RSA class
	String Bmessage, Amessage;																		//Variable for message to encrypt
	BigInteger Bplaintext, ciphertext, Aplaintext;
	if(choice == 0) {																				//This choice handles the Encryption
		int block_size;
		Scanner scanner_s = new Scanner (System.in);
		System.out.print("Enter the size (number of characters) of each block: ");
		block_size = scanner_s.nextInt();															//Takes in user input for block size, *NOTE* block size should be less than n/3
		Scanner scanner_m = new Scanner (System.in);
		System.out.print("Enter the message you would like to encrypt: ");							//Takes in user input of the message to encrypt
		Bmessage = scanner_m.nextLine();
		StringBuilder stringbuilder = new StringBuilder();
		for (char c : Bmessage.toCharArray()) {														//Loops through message appending ascii values
			if((int)c > 99) {													
				stringbuilder.append((int)c);														//appends ascii value
			}
			else {
				c = (char)((int)c + 900);															//if the ascii value of the character is less than 3 digits, 900 is added to the ascii value
				stringbuilder.append((int)c);														//append new value
			}
		}
		System.out.print("Message before encryption: \"" + Bmessage + "\"\n");						//Before Encryption
		Bplaintext = new BigInteger(stringbuilder.toString());										//Message gets converted from a String to a BigInteger
		System.out.print("Plaintext before encryption: " + Bplaintext + "\n");
		int length = Bplaintext.toString().length();												//Length of the plaintext
		//System.out.print("length = " + length + "\n");											//Prints the length of the plaintext, used for debugging
		double numBlocks = (length / block_size);													//Number of blocks in the plaintext based on the block size specified by the user
		numBlocks = numBlocks / block_size;
		numBlocks = (int)Math.ceil(numBlocks);
		//System.out.print("numBlocks = " + numBlocks + "\n");										//Prints the number of blocks, used for debugging 
		StringBuilder strBuild = new StringBuilder();
		String block;
		for (int i=0; i<numBlocks; i++) {															//Loops through the number of blocks in the plaintext
			if(i < numBlocks - 1) {
				block = Bplaintext.toString().substring((i * (block_size * 3)),(i*(block_size * 3))+(block_size * 3));
				//creates a substring starting at the beginning of the block and ending at the end of the block
			}
			else {
				if((length % (block_size * block_size))== 0) {										//Checks the last block to see if it is a full block or if it is only a partial block
					block = Bplaintext.toString().substring((i * (block_size * 3)),(i*(block_size * 3))+(block_size * 3));
					//if it is a full block, this creates a substring starting at the beginning of the block and ending at the end of the block, just like above
				}
				else {
					block = Bplaintext.toString().substring((i * (block_size * 3)),(i*(block_size * 3))+(length % (block_size * block_size)));
					//if it is a partial block, this creates a substring starting at the beginning of the block and uses modulous to determine the number of digits until the end of the block
				}
			}
			//System.out.print("block " + (i+1) + ": " + block + "\n");								//Prints the contents of each block, used for debugging
			ciphertext = application.Encryption(new BigInteger(block)); 							//Block gets Encrypted
			strBuild.append(ciphertext);															//Appends the encrypted block to a string of the previously encrypted blocks
			strBuild.append(" ");																	//Adds a space in between each block for padding
		}
		strBuild.deleteCharAt(strBuild.length() - 1);
		System.out.print("Ciphertext: " + strBuild.toString() + "\n");
	}
	else if(choice == 1) {																			//This choice handles the Decryption
		BigInteger d, n;
		Scanner scanner_x = new Scanner (System.in);
		System.out.print("Enter the ciphertext you would like to decrypt: ");
		String temp1 = scanner_x.nextLine();														//Takes in user input for ciphertext, *NOTE* make sure the leading " " (space character) is not included when pasting the ciphertext
		String temp2[];
		Scanner scanner_y = new Scanner (System.in);
		System.out.print("Enter the value of d: ");
		d = scanner_y.nextBigInteger();																//Takes in user input for d
		Scanner scanner_z = new Scanner (System.in);
		System.out.print("Enter the value of n: ");
		n = scanner_z.nextBigInteger();																//Takes in user input for n
		//System.out.print("temp 1: " + temp1 + "\n");												//Prints temp1, used for debugging
		temp2 = temp1.split("\\ ");																	//Populates temp2 with the ciphertext blocks that are separated by spaces in temp1
		//for(int k=0; k<temp2.length; k++) {														//Prints out each block in temp2, used for debugging
		//	System.out.print("temp2 " + k + ": " + temp2[k] + "\n");
		//}
		BigInteger Array[] = new BigInteger[temp2.length];											//BigInteger array to hold the decrypted blocks 
		for(int i=0; i<temp2.length; i++) {
			Array[i] = new BigInteger(temp2[i]);													//Creates a new BigInteger version of the string at that index in temp2 
			Array[i] = application.Decryption(Array[i], d, n);										//Message gets Decrypted
		}
		StringBuilder build = new StringBuilder();
		for(int j=0;j<Array.length;j++) {
			build.append(Array[j].toString());														//Appends the plaintext blocks together to form a plaintext message
		}
		Aplaintext = new BigInteger(build.toString());												//Converts string to a BigInteger
		System.out.print("Plaintext after decryption: " + Aplaintext.toString() + "\n");			//Prints the plaintext message
		Amessage = convertToString(Aplaintext);														//BigInteger gets converted from a BigInteger plaintext to a String equal to the original message
		System.out.print("Message after decryption: \"" + Amessage + "\"\n");						//Prints original message
	}
	else {
		System.out.print("ERROR: Not a valid choice, please re-run program.\n");					//This choice handles if neither Encryption or Decryption were selected
	}
	return;
	
	} //End of main
	
	//This function takes in an integer "size" (the number of digits of the prime number requested by the user)
	//and returns a random prime BigInteger of the specified size
	public BigInteger bigIntGen(int size) {
		Random r = new Random();
		BigInteger number = new BigInteger(bitCalculator(size), r);
		if(Fermats(number,6)) {
			return number;															//returns the generated BigInteger if it is prime
		}
		else {
			return BigInteger.valueOf(0);											//returns zero if the generated BigInteger is non-prime
		}
	}
	
	//This function takes in a BigInteger and a integer certainty 
	//and returns true if the BigInteger is prime and false otherwise
	public static boolean Fermats(BigInteger number, int certainty) {
		for (int i=0; i<certainty; i++) {
			if(!primeCheck(number)) {
				return false; 														//The number is found to be non-prime
			}
		}
		return true;																//The number is found to be prime based on certainty
	}
	
	//This function takes in a BigInteger and uses the BigInteger function
	//modPow() in order to determine if a number is prime
	//returns true if the number is prime for a specific test
	public static boolean primeCheck(BigInteger number) {
		Random r = new Random();													//Generate random number
		long rand = r.nextInt(800) + 1;												//convert to pseudorandom
		BigInteger random = BigInteger.valueOf(rand);								//convert to BigInteger
		random = random.modPow(number.subtract(BigInteger.valueOf(1)), number);		//random = (random ^(number-1)) % number
		boolean isPrime = random.equals(BigInteger.valueOf(1));						//True if random equals 1, false otherwise
		return isPrime;																//True if prime for this test, false otherwise
	}
	
	//This function takes in an integer "size" (the number of digits the user wants p or q to be) 
	//and returns the number of bits it will take to represent a number that size in binary 
	public int bitCalculator(int size) {
		BigInteger a = BigInteger.valueOf(10).pow(size).subtract(BigInteger.valueOf(1));
		//System.out.print("a = " + a + "\n");
		int bitCount = a.bitLength();
		//System.out.print("bitCount = " + bitCount + "\n");
		return bitCount - 1;
	}
	
	//This function takes in a BigInteger version of a plaintext block
	//and returns the BigInteger version of the block in ciphertext
	public BigInteger Encryption(BigInteger plainTextBlock) {
		return plainTextBlock.modPow(e, n);
	}
	
	//This function takes in a BigInteger version of a ciphertext block
	//and returns the BigInteger version of the block in plaintext
	public BigInteger Decryption(BigInteger cipherTextBlock, BigInteger d, BigInteger n) {
		return cipherTextBlock.modPow(d, n);
	}
	
	//This function takes in a BigInteger version of the plaintext message
	//and returns the String equivalent of the original message
	public static String convertToString(BigInteger message) {
		StringBuilder str = new StringBuilder();
		char c;
		while(message.compareTo(BigInteger.valueOf(0)) >= 1) {						//runs through loop until message is equal to zero
			c = (char)(message.mod(BigInteger.valueOf(1000)).longValue());			//takes 3 digits off of the BigInteger to get a char ascii value 
			if(c > 900) {															//if 900 had been previously added to the ascii value, subtract 900
				c = (char)((int)c - 900);
			}
			message = (message.divide(BigInteger.valueOf(1000)));					//removes 3 digits off of the BigInteger value before starting the loop over
			str.append(c);															//appends the character to the string in order to build the original message
		}
		str = str.reverse();														//stringbuilder builds the message in reverse order, this puts it in the correct order
		return str.toString();														//returns string version of the stringbuilder
	}
	
} //End of Class RSA_Crypt
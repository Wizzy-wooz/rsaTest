package com.mkyong.receiver;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;


public class VerifyMessage2 {
	private List<byte[]> list;

	@SuppressWarnings("unchecked")
	//The constructor of VerifyMessage class retrieves the byte arrays from the File and prints the message only if the signature is verified.
	public VerifyMessage2(String filename, String keyFile) throws Exception {
		ObjectInputStream in = new ObjectInputStream(new FileInputStream(filename));
	    this.list = (List<byte[]>) in.readObject();
	    in.close();
	    byte[] signature = {111, 49, 114, 107, -15, 72, 123, -77, 60, 52, 104, 78, 29, 29, -46, -49, -87,
				-82, -9, -84, -1, 66, -46, 44, 112, -50, 54, 2, 36, 99, -9, 13, -72, -54, 96, -118, -121,
				59, 36, 39, 22, 39, -44, 62, -111, 111, -18, -104, 2, 114, 103, -125, 75, 84, 72, -63, 114, 19,
				108, -85, 98, -114, -101, -40, 103, -94, -65, 70, 7, 107, 127, 89, -38, -64, -92, -50, -40, -65,
				-100, 72, -68, 64, 3, 82, 27, -56, 78, -2, 67, 93, -65, -65, -20, -6, 121, 70, -63, -9, -4,
				-126, -118, 119, -68, -99, -30, 5, 97, 81, -35, -53, -28, 4, 39, 16, 117, -108, 85, -111, 123,
				-16, -48, 77, -31, -55, 122, -50, 28, 117};
				byte[] data = {72, 101, 108, 108, 111};
		System.out.println(
	    		verifySignature(data, signature, keyFile) ?
						"VERIFIED MESSAGE" + "\n----------------\n" + new String(list.get(0)) :
						"Could not verify the signature.");
	}
	
	//Method for signature verification that initializes with the Public Key, updates the data to be verified and then verifies them using the signature
	private boolean verifySignature(byte[] data, byte[] signature, String keyFile) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(getPublic());
		//sig.initVerify(getPublic(keyFile));
		sig.update(data);
		
		return sig.verify(signature);
	}
	
	//Method to retrieve the Public Key from a file
	//public PublicKey getPublic(String filename) throws Exception {
	public PublicKey getPublic() throws Exception {
		/*byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);*/
		String modulusHex = "9c008cf9ef9a5d9de7ee52afb3460448a986b7de126baee0bdd2a9fca206c6030b6b72a3a9a5809a445639bcd50" +
				"344800f96d31308509567b83ddd5b453def0f422936bff0a850158bc0569d662de0dc4acbac50064cce695d1368c21a7d51c8d4b" +
				"7c0db595cfff36dcfae8ce9a9ce5317ee5702062c77ff7fb5d16134abbb01";
		BigInteger modulus = new BigInteger(modulusHex, 16);
		String exponentHex = "010001";
		BigInteger exponent = new BigInteger(exponentHex, 16);
		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exponent);
		KeyFactory keyFac = KeyFactory.getInstance("RSA");
		RSAPublicKey rsaPub = (RSAPublicKey) keyFac.generatePublic(pubKeySpec);
		System.out.println(rsaPub);
        return rsaPub;
	}
	
	public static void main(String[] args) throws Exception{
		new VerifyMessage2("MyData/SignedData.txt", "MyKeys/publicKey");
	}
}

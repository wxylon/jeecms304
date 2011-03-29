package com.jeecms.common.security.encoder;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;

/**
 * MD5密码加密
 */
public class Md5PwdEncoder implements PwdEncoder {
	
	/**
	 * 混淆码。防止破解。
	 */
	private String defaultSalt;
	
	public String encodePassword(String rawPass) {
		return encodePassword(rawPass, defaultSalt);
	}

	public String encodePassword(String rawPass, String salt) {
		String saltedPass = mergePasswordAndSalt(rawPass, salt, false);
		MessageDigest messageDigest = getMessageDigest();
		byte[] digest;
		try {
			digest = messageDigest.digest(saltedPass.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("UTF-8 not supported!");
		}
		return new String(Hex.encodeHex(digest));
	}

	public boolean isPasswordValid(String encPass, String rawPass) {
		return isPasswordValid(encPass, rawPass, defaultSalt);
	}

	public boolean isPasswordValid(String encPass, String rawPass, String salt) {
		if (encPass == null) {
			return false;
		}
		String pass2 = encodePassword(rawPass, salt);
		return encPass.equals(pass2);
	}

	protected final MessageDigest getMessageDigest() {
		String algorithm = "MD5";
		try {
			return MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalArgumentException("No such algorithm [" + algorithm + "]");
		}
	}

	/**
	 * 将密码和混淆码拼接类
	 * @param password	密码
	 * @param salt		混淆码
	 * @param strict	是否需要检查混淆码中包含<b>{</b> or <b>}</b>
	 * @return
	 */
	protected String mergePasswordAndSalt(String password, Object salt, boolean strict) {
		
		if (password == null) {
			password = "";
		}
		
		if (strict && (salt != null)) {
			if ((salt.toString().lastIndexOf("{") != -1) || (salt.toString().lastIndexOf("}") != -1)) {
				throw new IllegalArgumentException("Cannot use { or } in salt.toString()");
			}
		}
		
		if ((salt == null) || "".equals(salt)) {
			return password;
		} else {
			return password + "{" + salt.toString() + "}";
		}
	}

	/**
	 * 获得混淆码
	 * @return
	 */
	public String getDefaultSalt() {
		return defaultSalt;
	}

	/**
	 * 设置混淆码
	 * @param salt
	 */
	public void setSefaultSalt(String defaultSalt) {
		this.defaultSalt = defaultSalt;
	}
	
	public static void main(String[] args){
		Md5PwdEncoder md5PwdEncoder = new Md5PwdEncoder();
		System.out.println(md5PwdEncoder.mergePasswordAndSalt("sss","{sss}", true));
	}
}

package com.demo.rsa;

import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * java与node.js非对称加密
 * 
 * 出自：http://www.cnblogs.com/goodhelper
 * 
 * @author 刘冬
 *
 */
@RestController
public class MainController {

	/**
	 * 存储用户信息
	 */
	private Map<String, String> users = new ConcurrentHashMap<>();

	/**
	 * 存储session私钥
	 */
	private Map<String, String> session = new ConcurrentHashMap<>();

	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}

	@GetMapping("getUser")
	public String getUser(@RequestHeader(value = "Authorization", required = false) String token) {
		if (token == null) {
			return null;
		}
		return users.containsKey(token) ? users.get(token) : null;
	}

	@PostMapping("login")
	@Deprecated
	public Map<String, Object> login(@RequestBody Map<String, String> params) {
		Map<String, Object> result = new HashMap<>();
		if (!params.containsKey("account") || !params.containsKey("password")) {
			result.put("success", false);
			result.put("message", "请输入账号和密码");
			return result;
		}
		if (!"123456".equals(params.get("password"))) {
			result.put("success", false);
			result.put("message", "密码错误");
			return result;
		}

		String token = UUID.randomUUID().toString();
		users.put(token, params.get("account"));

		result.put("success", true);
		result.put("message", "登录成功");
		result.put("data", token);
		return result;
	}

	/**
	 * 获取session公钥
	 * 
	 * @return
	 */
	@GetMapping("getSession")
	public Map<String, String> getSession() throws Exception {
		String sessionId = UUID.randomUUID().toString();
		Map<String, String> result = new HashMap<>();
		result.put("sessionId", sessionId);

		String algorithm = "RSA";
		String privateKey = null, publicKey = null;

		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm);
		keyPairGen.initialize(512);
		KeyPair keyPair = keyPairGen.generateKeyPair();

		byte[] encoded = keyPair.getPrivate().getEncoded();
		PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(encoded);
		ASN1Encodable encodable = pkInfo.parsePrivateKey();
		ASN1Primitive primitive = encodable.toASN1Primitive();
		byte[] privateKeyPKCS1 = primitive.getEncoded();
		PemObject pemObject = new PemObject("RSA PRIVATE KEY", privateKeyPKCS1);
		try (StringWriter stringWriter = new StringWriter()) {
			try (PemWriter pemWriter = new PemWriter(stringWriter)) {
				pemWriter.writeObject(pemObject);
				pemWriter.flush();
				String pemString = stringWriter.toString();
				privateKey = pemString;
			}
		}

		encoded = keyPair.getPublic().getEncoded();
		SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(encoded);
		primitive = spkInfo.parsePublicKey();
		byte[] publicKeyPKCS1 = primitive.getEncoded();

		pemObject = new PemObject("RSA PUBLIC KEY", publicKeyPKCS1);
		try (StringWriter stringWriter = new StringWriter()) {
			try (PemWriter pemWriter = new PemWriter(stringWriter)) {
				pemWriter.writeObject(pemObject);
				pemWriter.flush();
				String pemString = stringWriter.toString();
				publicKey = pemString;
			}
		}

		// 记录私钥
		session.put(sessionId, privateKey);
		// 返回公钥
		result.put("publicKey", publicKey);

		return result;
	}

	@SuppressWarnings("unchecked")
	@PostMapping("loginByEncrypt")
	public Map<String, Object> loginByEncrypt(@RequestBody Map<String, String> params) {
		Map<String, Object> result = new HashMap<>();

		if (!params.containsKey("sessionId")) {
			result.put("success", false);
			result.put("message", "sessionId是必填参数");
			return result;
		}

		if (!params.containsKey("playload")) {
			result.put("success", false);
			result.put("message", "playload是必填参数");
			return result;
		}

		String sessionId = params.get("sessionId");

		if (!session.containsKey(sessionId)) {
			result.put("success", false);
			result.put("message", "无效session");
			return result;
		}

		Map<String, String> json = null;
		try {
			String privateKey = session.get(sessionId);
			String playload = params.get("playload");
			String text = decrypt(playload, privateKey);

			ObjectMapper mapper = new ObjectMapper();
			json = mapper.readValue(text, Map.class);
		} catch (Exception e) {
			e.printStackTrace();
		}

		if (json == null) {
			result.put("success", false);
			result.put("message", "非法请求");
			return result;
		}

		if (!json.containsKey("account") || !json.containsKey("password")) {
			result.put("success", false);
			result.put("message", "请输入账号和密码");
			return result;
		}
		if (!"123456".equals(json.get("password"))) {
			result.put("success", false);
			result.put("message", "密码错误");
			return result;
		}

		String token = UUID.randomUUID().toString();
		users.put(token, json.get("account"));

		result.put("success", true);
		result.put("message", "登录成功");
		result.put("data", token);
		return result;
	}

	/**
	 * 私钥解密
	 * 
	 * @param encode
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	private String decrypt(String text, String privateKey) throws Exception {
		String algorithm = "RSA";
		String keyText = privateKey.split("-----")[2].replaceAll("\n", "").replaceAll("\r", "");
		byte[] bytes = Base64.decode(keyText.getBytes());
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytes);
		PrivateKey key = keyFactory.generatePrivate(privateKeySpec);

		Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, key);

		byte[] doFinal = cipher.doFinal(Base64.decode(text));
		return new String(doFinal, "utf-8");
	}
}

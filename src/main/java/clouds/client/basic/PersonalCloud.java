package clouds.client.basic;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Properties;
import java.util.UUID;
import java.util.Vector;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringEscapeUtils;

import xdi2.client.XDIClient;
import xdi2.client.exceptions.Xdi2ClientException;
import xdi2.client.http.XDIHttpClient;
import xdi2.core.ContextNode;
import xdi2.core.Graph;
import xdi2.core.Literal;
import xdi2.core.Relation;
import xdi2.core.exceptions.Xdi2ParseException;
import xdi2.core.features.linkcontracts.PublicLinkContract;
import xdi2.core.features.linkcontracts.RootLinkContract;
import xdi2.core.features.nodetypes.XdiAbstractMemberUnordered;
import xdi2.core.features.nodetypes.XdiPeerRoot;
import xdi2.core.features.signatures.KeyPairSignature;
import xdi2.core.features.signatures.Signature;
import xdi2.core.features.signatures.Signatures;
import xdi2.core.impl.json.memory.MemoryJSONGraphFactory;
import xdi2.core.impl.memory.MemoryGraph;
import xdi2.core.impl.memory.MemoryGraphFactory;
import xdi2.core.io.XDIReader;
import xdi2.core.io.XDIReaderRegistry;
import xdi2.core.io.XDIWriter;
import xdi2.core.io.XDIWriterRegistry;
import xdi2.core.util.iterators.ReadOnlyIterator;
import xdi2.core.xri3.CloudNumber;
import xdi2.core.xri3.XDI3Segment;
import xdi2.core.xri3.XDI3Statement;
import xdi2.core.xri3.XDI3SubSegment;
import xdi2.discovery.XDIDiscoveryClient;
import xdi2.discovery.XDIDiscoveryResult;
import xdi2.messaging.GetOperation;
import xdi2.messaging.Message;
import xdi2.messaging.MessageEnvelope;
import xdi2.messaging.MessageResult;

import com.ibm.icu.util.StringTokenizer;

public class PersonalCloud {

	public static XDI3Segment XRI_S_DEFAULT_LINKCONTRACT = XDI3Segment
			.create("$do");

	public static String DEFAULT_REGISTRY_URI = "http://mycloud-ote.neustar.biz:12220/";

	private String secretToken = null;
	private XDI3Segment linkContractAddress = null;

	private XDI3Segment cloudNumber = null;
	private XDI3Segment cloudName = null;
	private XDI3Segment senderCloudNumber = XDI3Segment.create("$anon");
	private String registryURI = null;
	private String cloudEndpointURI = null;

	private Hashtable<String,ProfileInfo> profiles = new Hashtable<String,ProfileInfo>();
	private Hashtable<String, ContactInfo> addressBook = new Hashtable<String, ContactInfo>();

	private String sessionId = null;

	private PublicKey signaturePublicKey = null;
	private PrivateKey signaturePrivateKey = null;

	public static String DEFAULT_DIGEST_ALGORITHM = "sha";
	public static String DEFAULT_DIGEST_LENGTH = "256";
	public static String DEFAULT_KEY_ALGORITHM = "rsa";
	public static String DEFAULT_KEY_LENGTH = "2048";

	private static MemoryGraphFactory graphFactory;

	/*
	 * factory methods for opening personal clouds
	 */

	/**
	 * 
	 * @param cloudNameOrCloudNumber
	 * @param secretToken
	 * @param linkContractAddress
	 * @param regURI
	 * @return
	 */
	public static PersonalCloud open(XDI3Segment cloudNameOrCloudNumber,
			String secretToken, XDI3Segment linkContractAddress, String regURI,
			String session) {

		// like My Cloud Sign-in in clouds.projectdanbe.org
		// 1. discover the endpoint
		// 2. Load profile if available
		PersonalCloud pc = new PersonalCloud();
		XDIHttpClient httpClient = null;
		if (regURI != null && regURI.length() > 0) {
			httpClient = new XDIHttpClient(regURI);
			pc.registryURI = regURI;
		} else {
			httpClient = new XDIHttpClient(DEFAULT_REGISTRY_URI);
			pc.registryURI = DEFAULT_REGISTRY_URI;
		}
		XDIDiscoveryClient discovery = new XDIDiscoveryClient();
		discovery.setRegistryXdiClient(httpClient);
		try {

			XDIDiscoveryResult discoveryResult = discovery
					.discoverFromRegistry(cloudNameOrCloudNumber, null);
			// if the cloudName or cloudNumber is not registered in the
			// Registry, then return null
			if (discoveryResult.getCloudNumber() == null) {
				System.out
						.println("No Cloudnumber found in Discovery Result. Returning null.");
				return null;
			}

			CloudNumber cnum = discoveryResult.getCloudNumber();
			pc.cloudNumber = cnum.getXri();
			
			if (discoveryResult.getXdiEndpointUri() == null) {
				System.out
						.println("No XDI endpoint URI found in Discovery Result. Returning null.");
				return null;
			}
			pc.cloudEndpointURI = discoveryResult.getXdiEndpointUri();
			pc.setSignaturePublicKey(discoveryResult.getSignaturePublicKey());
			//pc.linkContractAddress = linkContractAddress;
			pc.senderCloudNumber = pc.cloudNumber;
			if(linkContractAddress.toString().equalsIgnoreCase("$do")){
				pc.linkContractAddress = RootLinkContract.createRootLinkContractXri(pc.cloudNumber);
			} else if (linkContractAddress.toString().equalsIgnoreCase("$public$do")) {
				pc.linkContractAddress = PublicLinkContract.createPublicLinkContractXri(pc.cloudNumber);
			} else {
			
				pc.linkContractAddress = linkContractAddress;
			}
			
			System.out.println(pc.toString());
			if (secretToken != null && !secretToken.isEmpty()) {
				pc.secretToken = secretToken;
				//TBD : find out less costly ways of making sure that the secret token is good
//				XDI3Segment authorityNodeAddr = XDI3Segment
//						.create(pc.cloudNumber.toString());
//
//				MessageResult result = pc.getXDIStmtsNoSig(authorityNodeAddr,
//						false);
//				MemoryGraph response = (MemoryGraph) result.getGraph();
//				if (response == null
//						|| response.getRootContextNode() == null
//						|| response.getRootContextNode()
//								.getAllContextNodeCount() == 0) {
//					return null;
//				}

			}
			if(cloudNameOrCloudNumber.toString().startsWith("=") || cloudNameOrCloudNumber.toString().startsWith("@") || cloudNameOrCloudNumber.toString().startsWith("*")){
				pc.setCloudName(cloudNameOrCloudNumber);
			}
			
			pc.sessionId = session;
		} catch (Xdi2ClientException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		} finally {
			httpClient.close();
		}
		return pc;
	}

	public static PersonalCloud open(XDI3Segment cloudNameOrCloudNumber,
			String secretToken, XDI3Segment linkContractAddress, String regURI) {
		return PersonalCloud.open(cloudNameOrCloudNumber, secretToken,
				linkContractAddress, regURI, null);
	}

	@Override
	public String toString() {

		StringBuffer str = new StringBuffer();
		str.append("\n");
		str.append("CloudNumber\t:\t" + cloudNumber);
		str.append("\n");
		str.append("registryURI\t:\t" + registryURI);
		str.append("\n");
		try {
			if (cloudEndpointURI != null) {
				str.append("Cloud endpoint URI\t:\t"
						+ URLDecoder.decode(cloudEndpointURI, "UTF-8"));
			}
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			str.append("Cloud endpoint URI\t:\tnull");
			e.printStackTrace();
		}
		str.append("\n");
		str.append("Link Contract Address\t:\t" + linkContractAddress);
		str.append("\n");

		return str.toString();

	}

	/**
	 * Open a peer cloud
	 * 
	 * @param cloudNameOrCloudNumber
	 *            : The cloudName/Number for the peer cloud
	 * @param senderCN
	 *            : Messages will have this cloudNumber as source
	 * @param linkContractAddress
	 * @param regURI
	 * @return
	 */
	public static PersonalCloud open(XDI3Segment cloudNameOrCloudNumber,
			XDI3Segment senderCN, XDI3Segment linkContractAddress, String regURI) {

		PersonalCloud pc = PersonalCloud.open(cloudNameOrCloudNumber, "",
				linkContractAddress, regURI);

		if (pc != null) {
			pc.senderCloudNumber = senderCN;
		}
		return pc;
	}

	public static String findCloudNumber(String cloudName, String regURI) {
		XDIDiscoveryResult discoveryResult = null;
		XDIHttpClient httpClient = null;
		if (regURI != null && regURI.length() > 0) {
			httpClient = new XDIHttpClient(regURI);

		} else {
			httpClient = new XDIHttpClient(DEFAULT_REGISTRY_URI);

		}
		XDIDiscoveryClient discovery = new XDIDiscoveryClient();
		discovery.setRegistryXdiClient(httpClient);
		try {

			discoveryResult = discovery.discoverFromRegistry(
					XDI3Segment.create(cloudName), null);

		} catch (Xdi2ClientException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} finally {
			httpClient.close();
		}

		return discoveryResult != null ? discoveryResult.getCloudNumber()
				.toString() : "";
	}

	public Graph getWholeGraph() {

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope for getting email

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		message.setSecretToken(secretToken);
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		message.createGetOperation(XDI3Segment.create(""));
		message = this.signMessage(message);

		System.out.println();
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.out.println();
		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			System.out.println("**************Graph Start***************\n");
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);
			System.out.println("\n**************Graph End***************");

			return response;

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}

		return null;

	}

	public ArrayList<PCAttributeCollection> geAllCollections() {

		Graph g = this.getWholeGraph();
		ContextNode root = g.getRootContextNode();
		ReadOnlyIterator<Literal> allLiterals = root.getAllLiterals();
		while (allLiterals.hasNext()) {
			Literal lit = allLiterals.next();
			String value = lit.getLiteralData().toString();
			String name = lit.getContextNode().toString();
		}
		return null;

	}

	/**
	 * 
	 * @param profileInfo
	 */

	public void createNewProfile(ProfileInfo profileInfo) {

		// construct the statements for Profiles's fields

		if(this.getProfileInfo(profileInfo.getRelativeXDIAddress() )!= null){
			
			this.updateProfileInfo(profileInfo);
			return;
		}
		String uuid = UUID.randomUUID().toString();
		uuid = "!:uuid:" + uuid;
		ArrayList<XDI3Statement> profileXDIStmts = new ArrayList<XDI3Statement>();

		if (profileInfo.getEmail() != null) {
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString() + "[+profile]" + uuid 
					+ "<+email>&/&/\"" + profileInfo.getEmail() + "\""));
		}
		if (profileInfo.getPhone() != null) {
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString() + "[+profile]" + uuid
					+ "<+phone>&/&/\"" + profileInfo.getPhone() + "\""));
		}
		if (profileInfo.getName() != null) {
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString() + "[+profile]" + uuid
					+ "<+name>&/&/\"" + profileInfo.getName() + "\""));
		}
		
		//for event notifications
		profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString() + "[+profile]" + uuid
						+ "<+flag+all+event+notification>&/&/\"" + "Y" + "\""));
		profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString() + "[+profile]" + uuid
				+ "<+flag+major+event+notification>&/&/\"" + "N" + "\""));
		profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString() + "[+profile]" + uuid
				+ "<+filter+event+notification>&/&/\"" + "NONE" + "\""));
		
		if(profileInfo.getRelativeXDIAddress() != null && !profileInfo.getRelativeXDIAddress().isEmpty()) {
			//create the relative address as a context with $rep to the profile context
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString()  +  profileInfo.getRelativeXDIAddress() + "/$rep/" + cloudNumber.toString() + "[+profile]" + uuid 
					));
			//create a public link contract to this context so that this context is readable to everyone
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString()  +"$to$anon$from$public$do" +"/" +  "$get" + "/" + cloudNumber.toString() + "[+profile]" + uuid 
					));
			
			//create a public link contract to the named context so that the context is readable to everyone
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString()  +"$to$anon$from$public$do" +"/" +  "$get" + "/" +   cloudNumber.toString()  +  profileInfo.getRelativeXDIAddress() 
					));
			String respectConnectXDIMessage = this.createRespectConnectRequest(profileInfo.getRelativeXDIAddress());
			
			profileXDIStmts.add(XDI3Statement.fromLiteralComponents(XDI3Segment.create(cloudNumber.toString() + "[+profile]" + uuid + "<+connect>&"), respectConnectXDIMessage));
			profileInfo.setRespectConnectXDIMessage(respectConnectXDIMessage);
		}
		if(profileInfo.isDefault()){
			//create the relative address as a context with $rep to the profile context
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString()  +  "+default+profile" + "/$rep/" + cloudNumber.toString() + "[+profile]" + uuid 
					));
			//create a public link contract to the named context so that the context is readable to everyone
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString()  +"$to$anon$from$public$do" +"/" +  "$get" + "/" +   cloudNumber.toString()  +  "+default+profile" 
					));
			
		}
		
		
		
		// send the message

		// prepare XDI client

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);

		message.setSecretToken(secretToken);

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));
		message.createSetOperation(profileXDIStmts.iterator());

		System.out.println("Message :\n" + messageEnvelope + "\n");

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			System.out.println(messageResult);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}

		profileInfo.setProfileContextId(cloudNumber.toString() + "[+profile]" + uuid);
		profiles.put(profileInfo.getProfileContextId(),  profileInfo);

	}

	public void deleteProfile(String contextId){
		
		XDI3Segment xdiNode = XDI3Segment.create(this.cloudNumber + contextId);
		
		this.deleteNodeTree(xdiNode);
	}
	public String getDataBucket(String bucketName) {
		String values = new String();

		XDI3Segment query = XDI3Segment.create(cloudNumber + "[<+" + bucketName
				+ ">]");
		MessageResult result = getXDIStmts(query, true);

		MemoryGraph response = (MemoryGraph) result.getGraph();
		ContextNode root = response.getRootContextNode();
		ReadOnlyIterator<Literal> literals = root.getAllLiterals();
		while (literals.hasNext()) {
			Literal literal = literals.next();

			values += literal.getLiteralDataString();
			values += ";";
		}

		return values;
	}

	/*
	 * Update Attributes (phone,email etc.) of a profile
	 */
	public void updateProfileInfo(ProfileInfo newProfile){
		
		String contextId = newProfile.getProfileContextId();
		ArrayList<XDI3Statement> profileXDIStmts = new ArrayList<XDI3Statement>();

		if (newProfile.getEmail() != null && !newProfile.getEmail().isEmpty()) {
			profileXDIStmts.add(XDI3Statement.create(contextId 
					+ "<+email>&/&/\"" + newProfile.getEmail() + "\""));
		}
		if (newProfile.getPhone() != null && !newProfile.getPhone().isEmpty()) {
			profileXDIStmts.add(XDI3Statement.create(contextId
					+ "<+phone>&/&/\"" + newProfile.getPhone() + "\""));
		}
		if (newProfile.getName() != null && !newProfile.getName().isEmpty()) {
			profileXDIStmts.add(XDI3Statement.create(contextId
					+ "<+name>&/&/\"" + newProfile.getName() + "\""));
		}
		if(newProfile.isDefault()){
			//create the relative address as a context with $rep to the profile context
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString()  +  "+default+profile" + "/$rep/" + contextId 
					));
			//create a public link contract to the named context so that the context is readable to everyone
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString()  +"$to$anon$from$public$do" +"/" +  "$get" + "/" +   cloudNumber.toString()  +  "+default+profile" 
					));
			
		}

		if(newProfile.getRespectConnectXDIMessage() != null && !newProfile.getRespectConnectXDIMessage().isEmpty()){

			profileXDIStmts.add(XDI3Statement.fromLiteralComponents(XDI3Segment.create(contextId + "<+connect>&"), newProfile.getRespectConnectXDIMessage()));
		}
		// send the message

		// prepare XDI client

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);

		message.setSecretToken(secretToken);

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));
		message.createSetOperation(profileXDIStmts.iterator());

		System.out.println("Message :\n" + messageEnvelope + "\n");

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			System.out.println(messageResult);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}

		
		profiles.put(newProfile.getProfileContextId(),  newProfile);

		
	}
	public ProfileInfo getProfileInfo(String relativeXDIAddress) {

		ProfileInfo profileInfo = null; 

		// prepare XDI client to get profile info

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope for getting email

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(senderCloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		if (secretToken != null) {
			message.setSecretToken(secretToken);
		}
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		
		XDI3Segment targetCtxNode = XDI3Segment.create(cloudNumber.toString()
				+  relativeXDIAddress);
		message.createGetOperation(targetCtxNode);
		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// send the message

		
		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);
			
			if(response.getRootContextNode().getAllContextNodeCount() < 2 || response.getDeepContextNode(XDI3Segment.create("$false")) != null){
				return null;
			}
			profileInfo = new ProfileInfo();
			Literal phoneLiteral = response.getDeepLiteral(XDI3Segment
					.create(targetCtxNode.toString() + "<+phone>&"));
			String phone = (phoneLiteral == null) ? "" : phoneLiteral
					.getLiteralData().toString();
			profileInfo.setPhone(phone);
			Literal emailLiteral = response.getDeepLiteral(XDI3Segment
					.create(targetCtxNode.toString() + "<+email>&"));
			String email = (emailLiteral == null) ? "" : emailLiteral
					.getLiteralData().toString();
			profileInfo.setEmail(email);
			Literal nameLiteral = response.getDeepLiteral(XDI3Segment
					.create(targetCtxNode.toString() + "<+name>&"));
			String name = (nameLiteral == null) ? "" : nameLiteral
					.getLiteralData().toString();
			profileInfo.setName(name);
			Literal connectLiteral = response.getDeepLiteral(XDI3Segment
					.create(targetCtxNode.toString() + "<+connect>&"));
			String connect = (connectLiteral == null) ? "" : connectLiteral
					.getLiteralData().toString();
			profileInfo.setRespectConnectXDIMessage(connect);
			//System.out.println("\n\nProfile Connect " + connect + "\n\n");
			

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}
		if(profileInfo != null){
			profileInfo.setCloudNumber(this.cloudNumber.toString());
			profileInfo.setRelativeXDIAddress(relativeXDIAddress);
			profileInfo.setProfileContextId(targetCtxNode.toString());
			profiles.put(targetCtxNode.toString(),  profileInfo);
		}
		return profileInfo;
	}

	public MessageResult setXDIStmts(ArrayList<XDI3Statement> XDIStmts) {

		// prepare XDI client

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(this.senderCloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		//System.out.println("setXDIStmts 2");
		if (secretToken != null) {
			message.setSecretToken(secretToken);
			message = this.signMessage(message);
		}
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(this.cloudNumber));

		if (XDIStmts != null && XDIStmts.size() > 0) {
			message.createSetOperation(XDIStmts.iterator());
		}

		
		System.out.println();
		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println();
		// send the message

		MessageResult messageResult = null;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			//System.out.println("setXDIStmts 4");
			// System.out.println(messageResult);
			try {
				XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
						messageResult.getGraph(), System.out);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}
		return messageResult;
	}

//	public MessageResult setXDISegment(XDI3Segment targetSegment) {
//
//		// prepare XDI client
//
//		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);
//
//		// prepare message envelope
//
//		MessageEnvelope messageEnvelope = new MessageEnvelope();
//		Message message = messageEnvelope.createMessage(cloudNumber, 0);
//		message.setLinkContractXri(linkContractAddress);
//
//		message.setSecretToken(secretToken);
//
//		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));
//		message.createSetOperation(targetSegment);
//
//		// System.out.println("Message :\n" + messageEnvelope + "\n");
//		try {
//			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
//					messageEnvelope.getGraph(), System.out);
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//
//		// send the message
//
//		MessageResult messageResult = null;
//
//		try {
//
//			messageResult = xdiClient.send(messageEnvelope, null);
//			// System.out.println(messageResult);
//			try {
//				XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
//						messageResult.getGraph(), System.out);
//			} catch (IOException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//
//		} catch (Xdi2ClientException ex) {
//
//			ex.printStackTrace();
//		} catch (Exception ex) {
//
//			ex.printStackTrace();
//		} finally {
//			xdiClient.close();
//		}
//		return messageResult;
//	}

	public MessageResult delXDIStmts(ArrayList<XDI3Statement> XDIStmts,
			XDI3Segment target) {

		// prepare XDI client

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);

		message.setSecretToken(secretToken);

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));
		if (XDIStmts != null && XDIStmts.size() > 0) {
			message.createDelOperation(XDIStmts.iterator());
		}
		if (target != null && !target.toString().isEmpty()) {
			message.createDelOperation(target);
		}

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// send the message

		MessageResult messageResult = null;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			try {
				XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
						messageResult.getGraph(), System.out);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}
		return messageResult;
	}

	public MessageResult sendQueries(ArrayList<XDI3Segment> queries,
			ArrayList<XDI3Statement> queryStmts, boolean isDeref) {

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(senderCloudNumber, 0);
		if(linkContractAddress != null && linkContractAddress.toString().equals("$do")){
			linkContractAddress = RootLinkContract.createRootLinkContractXri(cloudNumber);
		}
		message.setLinkContractXri(linkContractAddress);
		if (secretToken != null) {
			message.setSecretToken(secretToken);
		}
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		if (queries != null && queries.size() > 0) {
			Iterator<XDI3Segment> queryIter = queries.iterator();
			while (queryIter.hasNext()) {
				XDI3Segment query = queryIter.next();
				GetOperation getOp = message.createGetOperation(query);
				
				if (isDeref) {
					getOp.setParameter(GetOperation.XRI_S_PARAMETER_DEREF, true);
				}
			}
		}
		if (queryStmts != null && queryStmts.size() > 0) {
			message.createGetOperation(queryStmts.iterator());
		}

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//sign the message
		message = this.signMessage(message);
		
		// send the message

		MessageResult messageResult = null;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}
		return messageResult;
	}

	public MessageResult getXDIStmts(XDI3Segment query, boolean isDeref) {

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = this.buildMessage(query, isDeref,
				true);
		MessageResult messageResult = null;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}
		return messageResult;
	}

	public MessageEnvelope buildMessage(XDI3Segment query, boolean isDeref,
			boolean withSignature) {
		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(senderCloudNumber, 0);
		if(linkContractAddress != null && linkContractAddress.toString().equals("$do")){
			linkContractAddress = RootLinkContract.createRootLinkContractXri(cloudNumber);
		}
		message.setLinkContractXri(linkContractAddress);
		if (secretToken != null) {
			message.setSecretToken(secretToken);
		}
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		GetOperation getOp = message.createGetOperation(query);
		if (isDeref) {
			getOp.setParameter(GetOperation.XRI_S_PARAMETER_DEREF, true);
		}
		if (withSignature) {
			message = this.signMessage(message);
		}
		// System.out.println("Message :\n" + messageEnvelope + "\n");
		System.out.println();
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println();
		return messageEnvelope;
	}

	public MessageResult getXDIStmtsNoSig(XDI3Segment query, boolean isDeref) {

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = this.buildMessage(query, isDeref,
				false);
		MessageResult messageResult = null;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}
		return messageResult;
	}

	/*
	 * contact info
	 */

	public void saveContactInfo(XDI3Segment cloudNameOrCloudNumber,
			ContactInfo contactInfo) {
		// construct the statements for Contact's fields

		PersonalCloud contactPC = PersonalCloud.open(cloudNameOrCloudNumber,
				cloudNumber, XDI3Segment.create("$public$do"), "");
		XDI3Segment contactCN = contactPC.cloudNumber;

		ArrayList<XDI3Statement> contactXDIStmts = new ArrayList<XDI3Statement>();

		if (contactInfo.getEmail() != null) {
			contactXDIStmts.add(XDI3Statement.create(contactCN.toString()
					+ "<+email>&/&/\"" + contactInfo.getEmail() + "\""));
		}
		if (contactInfo.getPhone() != null) {
			contactXDIStmts.add(XDI3Statement.create(contactCN.toString()
					+ "+home<+phone>&/&/\"" + contactInfo.getPhone() + "\""));
		}
		// send the message

		// prepare XDI client

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);

		message.setSecretToken(secretToken);

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));
		message.createSetOperation(contactXDIStmts.iterator());

		System.out.println("Message :\n" + messageEnvelope + "\n");

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			System.out.println(messageResult);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		}

		addressBook.put(contactCN.toString(), contactInfo);

	}

	public PCAttribute readAttr(PCAttributeCollection coll, String attrName) {

		// prepare XDI client to get profile info

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(senderCloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		if (secretToken != null) {
			message.setSecretToken(secretToken);
		}
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		message.createGetOperation(XDI3Segment.create(cloudNumber.toString()
				+ "+" + coll.getName() + "<+" + attrName + ">&"));

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);
			Literal literalValue = response.getDeepLiteral(XDI3Segment
					.create(cloudNumber.toString() + "+" + coll.getName()
							+ "<+" + attrName + ">&"));
			String strVal = (literalValue == null) ? "" : literalValue
					.getLiteralData().toString();
			PCAttribute attr = new PCAttribute(attrName, strVal, coll);
			return attr;

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		}

		return null;
	}

	public void deleteAttr(PCAttributeCollection coll, String attrName) {

		// prepare XDI client to get profile info

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(senderCloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		if (secretToken != null) {
			message.setSecretToken(secretToken);
		}
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		message.createDelOperation(XDI3Segment.create(cloudNumber.toString()
				+ "+" + coll.getName() + "<+" + attrName + ">&"));

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		}
		coll.deleteAttribute(attrName);

	}

	public void save(PCAttributeCollection coll) {
		// construct the statements for Profiles's fields

		ArrayList<XDI3Statement> profileXDIStmts = new ArrayList<XDI3Statement>();

		// for all attributes in the collection, create XDI statements
		Hashtable<String, PCAttribute> attrMap = coll.getAttributeMap();
		Iterator<PCAttribute> iter = attrMap.values().iterator();
		while (iter.hasNext()) {
			PCAttribute attr = iter.next();
			if (attr.getValue() != null) {
				XDI3Statement stmt = XDI3Statement.create(attr.getAddress(this)
						.toString() + "/&/\"" + attr.getValue() + "\"");
				profileXDIStmts.add(stmt);
			} else {
				XDI3Statement stmt = XDI3Statement.create(attr.getAddress(this)
						.toString() + "/&/\"" + "\"");
				profileXDIStmts.add(stmt);

			}
		}

		// send the message

		// prepare XDI client

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);

		message.setSecretToken(secretToken);

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		message.createSetOperation(profileXDIStmts.iterator());

		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// System.out.println("Message :\n" + messageEnvelope + "\n");

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			System.out.println(messageResult);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		}

	}

	public ContactInfo getContactInfo(XDI3Segment cloudNameOrCloudNumber) {

		return null;
	}

	public ContactInfo findContactInfoById(String id) {

		return null;
	}

	public ContactInfo findContactInfoByEmail(String email) {

		return null;
	}

	public void setLinkContractAddress(XDI3Segment linkContractAddress) {
		this.linkContractAddress = linkContractAddress;
	}

	/*
	 * access control
	 */

	/**
	 * 
	 * @param entity
	 *            The entity (e.g. ProfileInfo, ContactInfo, etc.) to allow
	 *            access to
	 * @param permissionXri
	 *            The allowed XDI operation, e.g. $get, $set, $del. If null, no
	 *            access is allowed.
	 * @param assignee
	 *            The Cloud Name or Cloud Number of the assigned
	 *            people/organization. If null, allow public access.
	 */
	public void allowAccess(PersonalCloudEntity entity,
			XDI3Segment permissionXri, XDI3Segment assignee) {

		PersonalCloud assigneePC = PersonalCloud.open(assignee, cloudNumber,
				XDI3Segment.create("$public$do"), "");
		XDI3Segment assigneeCN = assigneePC.cloudNumber;

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope for getting email

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		message.setSecretToken(secretToken);
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		message.createSetOperation(XDI3Statement.create(assigneeCN.toString()
				+ "$do$if$and/$true/({$from}/$is/" + assigneeCN.toString()
				+ ")"));
		message.createSetOperation(XDI3Statement.create(assigneeCN.toString()
				+ "$do/" + permissionXri.toString() + "/"
				+ entity.getAddress(this)));

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			xdiClient.close();
		}

		xdiClient = new XDIHttpClient(cloudEndpointURI);
		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}

	}

	public void deleteNodeTree(XDI3Segment target) {
		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		message.setSecretToken(secretToken);
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));
		message.createDelOperation(target);

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}

	}

	public void removeAccess(PersonalCloudEntity entity, XDI3Segment assignee) {
		PersonalCloud assigneePC = PersonalCloud.open(assignee, cloudNumber,
				XDI3Segment.create("$public$do"), "");
		XDI3Segment assigneeCN = assigneePC.cloudNumber;

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope for deleting the link contract for the
		// assignee

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		message.setSecretToken(secretToken);
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		// message.createDelOperation(XDI3Statement.create(assigneeCN.toString()
		// + "$do$if$and/$true/({$from}/$is/" + assigneeCN.toString()
		// + ")"));
		message.createDelOperation(XDI3Segment.create(assigneeCN.toString()
				+ "$do"));

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}

	}

	public String requestForAccess(XDI3Segment requestedObjectXri,
			XDI3Segment operation, XDI3Segment fromRelationshipXri,
			XDI3Segment toRelationshipXri, PersonalCloud peerCloud) {

		XDIClient xdiClient = new XDIHttpClient(peerCloud.getCloudEndpointURI());
		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(XDI3Segment
				.create("$public[+pendingrequest]$do"));

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(peerCloud
				.getCloudNumber()));

		String reqUUID = "!:uuid:" + UUID.randomUUID().toString();

		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+from_cn>&/&/\"" + cloudNumber.toString() + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID + "<+to_cn>&/&/\""
						+ peerCloud.getCloudNumber() + "\""));

		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+from_rel>&/&/\"" + fromRelationshipXri.toString()
						+ "\""));

		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+to_rel>&/&/\"" + toRelationshipXri.toString()
						+ "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+requested_object>&/&/\""
						+ requestedObjectXri.toString() + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+requested_op>&/&/\"" + operation.toString() + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+requestor_link_contract>&/&/\"" + cloudNumber
						+ toRelationshipXri.toString() + "$do" + "\""));
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "";
		}

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
			return "";
		} catch (Exception ex) {

			ex.printStackTrace();
			return "";
		} finally {
			xdiClient.close();
		}

		// create a pending request entry in sender's graph
		xdiClient = new XDIHttpClient(getCloudEndpointURI());
		messageEnvelope = new MessageEnvelope();
		message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		message.setSecretToken(secretToken);
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+from_cn>&/&/\"" + cloudNumber.toString() + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+from_rel>&/&/\"" + fromRelationshipXri.toString()
						+ "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID + "<+to_cn>&/&/\""
						+ peerCloud.getCloudNumber() + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+to_rel>&/&/\"" + toRelationshipXri.toString()
						+ "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+requested_object>&/&/\""
						+ requestedObjectXri.toString() + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+requested_op>&/&/\"" + operation.toString() + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+pendingrequest]" + reqUUID
						+ "<+requestor_link_contract>&/&/\"" + cloudNumber
						+ toRelationshipXri.toString() + "$do" + "\""));
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "";
		}

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
			return "";
		} catch (Exception ex) {

			ex.printStackTrace();
			return "";
		} finally {
			xdiClient.close();
		}
		// create the reciprocal relationship in requester graph
		createRelationship(peerCloud.getCloudNumber(), toRelationshipXri,
				fromRelationshipXri);

		// create requested object XRI under the peerCloud id in requester graph

		xdiClient = new XDIHttpClient(getCloudEndpointURI());
		messageEnvelope = new MessageEnvelope();
		message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		message.setSecretToken(secretToken);
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		message.createSetOperation(XDI3Statement.create(peerCloud
				.getCloudNumber()
				+ "[<+shared_data>]"
				+ "<"
				+ reqUUID
				+ ">"
				+ "&/&/\"" + requestedObjectXri.toString() + "\""));

		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return "";
		}

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
			return "";
		} catch (Exception ex) {

			ex.printStackTrace();
			return "";
		} finally {
			xdiClient.close();
		}

		return new String("$public[+pendingrequest]" + reqUUID);
	}

	public boolean approveAccess(XDI3Segment requestIdXri,
			XDI3Segment mappedTarget) {

		String from = "", to = "", from_rel = "", to_rel = "", operation = "", requested_object = "";
		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);
		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		message.setSecretToken(secretToken);
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		message.createGetOperation(requestIdXri);

		try {
			XDIWriterRegistry.forFormat("XDI/JSON", null).write(
					messageEnvelope.getGraph(), System.out);

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);
			// parse the response and get the five components of a request
			from = response.getDeepLiteral(XDI3Segment.create(requestIdXri
					+ "<+from_cn>&")) != null ? response.getDeepLiteral(
					XDI3Segment.create(requestIdXri + "<+from_cn>&"))
					.getLiteralDataString() : "";
			operation = response.getDeepLiteral(XDI3Segment.create(requestIdXri
					+ "<+requested_op>&")) != null ? response.getDeepLiteral(
					XDI3Segment.create(requestIdXri + "<+requested_op>&"))
					.getLiteralDataString() : "";
			from_rel = response.getDeepLiteral(XDI3Segment.create(requestIdXri
					+ "<+from_rel>&")) != null ? response.getDeepLiteral(
					XDI3Segment.create(requestIdXri + "<+from_rel>&"))
					.getLiteralDataString() : "";
			to_rel = response.getDeepLiteral(XDI3Segment.create(requestIdXri
					+ "<+to_rel>&")) != null ? response.getDeepLiteral(
					XDI3Segment.create(requestIdXri + "<+to_rel>&"))
					.getLiteralDataString() : "";
			requested_object = response.getDeepLiteral(XDI3Segment
					.create(requestIdXri + "<+requested_object>&")) != null ? response
					.getDeepLiteral(
							XDI3Segment.create(requestIdXri
									+ "<+requested_object>&"))
					.getLiteralDataString() : "";
			to = response.getDeepLiteral(XDI3Segment.create(requestIdXri
					+ "<+to_cn>&")) != null ? response.getDeepLiteral(
					XDI3Segment.create(requestIdXri + "<+to_cn>&"))
					.getLiteralDataString() : "";

			String jsonStr = response.toString("XDI/JSON", null);
			System.out.println(jsonStr);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
			return false;
		} catch (Exception ex) {

			ex.printStackTrace();
			return false;
		} finally {
			xdiClient.close();
		}

		// approve the request
		this.allowAccessToRelationship(XDI3Segment.create(requested_object),
				mappedTarget, XDI3Segment.create(operation),
				XDI3Segment.create(from_rel), XDI3Segment.create(to_rel),
				XDI3Segment.create(from));

		// delete the request
		xdiClient = new XDIHttpClient(cloudEndpointURI);
		MessageEnvelope delMessageEnvelope = new MessageEnvelope();
		Message delMessage = delMessageEnvelope.createMessage(cloudNumber, 0);
		delMessage.setLinkContractXri(linkContractAddress);
		delMessage.setSecretToken(secretToken);
		delMessage.setToPeerRootXri(XdiPeerRoot
				.createPeerRootArcXri(cloudNumber));

		delMessage.createDelOperation(requestIdXri);

		MessageResult delMessageResult;

		try {

			delMessageResult = xdiClient.send(delMessageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) delMessageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
			return false;
		} catch (Exception ex) {

			ex.printStackTrace();
			return false;
		} finally {
			xdiClient.close();
		}
		// send a message to peer cloud that the request has been approved
		PersonalCloud peerCloud = PersonalCloud.open(XDI3Segment.create(from),
				cloudNumber, XDI3Segment.create("$public$do"), null);

		xdiClient = new XDIHttpClient(peerCloud.getCloudEndpointURI());
		messageEnvelope = new MessageEnvelope();
		message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(XDI3Segment
				.create("$public[+approvedrequest]$do"));

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(peerCloud
				.getCloudNumber()));

		String reqUUID = requestIdXri.getLastSubSegment().toString();

		message.createSetOperation(XDI3Statement
				.create("$public[+approvedrequest]" + reqUUID
						+ "<+from_cn>&/&/\"" + from + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+approvedrequest]" + reqUUID
						+ "<+from_rel>&/&/\"" + from_rel + "\""));

		message.createSetOperation(XDI3Statement
				.create("$public[+approvedrequest]" + reqUUID
						+ "<+to_rel>&/&/\"" + to_rel + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+approvedrequest]" + reqUUID
						+ "<+requested_object>&/&/\"" + requested_object + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+approvedrequest]" + reqUUID
						+ "<+requested_op>&/&/\"" + operation + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+approvedrequest]" + reqUUID
						+ "<+to_cn>&/&/\"" + to + "\""));
		message.createSetOperation(XDI3Statement
				.create("$public[+approvedrequest]" + reqUUID
						+ "<+acceptor_link_contract>&/&/\"" + cloudNumber
						+ from_rel + "$do" + "\""));

		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

		// send the message

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
			return false;
		} catch (Exception ex) {

			ex.printStackTrace();
			return false;
		} finally {

			xdiClient.close();
		}

		// send another message to peer cloud to delete the pending request
		xdiClient = new XDIHttpClient(peerCloud.getCloudEndpointURI());

		messageEnvelope = new MessageEnvelope();
		message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(XDI3Segment
				.create("$public[+pendingrequest]$do"));

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(peerCloud
				.getCloudNumber()));

		message.createDelOperation(XDI3Segment
				.create("$public[+pendingrequest]" + reqUUID));
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

		// send the message

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
			return false;
		} catch (Exception ex) {

			ex.printStackTrace();
			return false;
		} finally {
			xdiClient.close();
		}

		return true;
	}

	public boolean denyAccess(XDI3Segment requestIdXri) {
		// delete the request
		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);
		MessageEnvelope delMessageEnvelope = new MessageEnvelope();
		Message delMessage = delMessageEnvelope.createMessage(cloudNumber, 0);
		delMessage.setLinkContractXri(linkContractAddress);
		delMessage.setSecretToken(secretToken);
		delMessage.setToPeerRootXri(XdiPeerRoot
				.createPeerRootArcXri(cloudNumber));

		delMessage.createDelOperation(requestIdXri);

		MessageResult delMessageResult;

		try {

			delMessageResult = xdiClient.send(delMessageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) delMessageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
			return false;
		} catch (Exception ex) {

			ex.printStackTrace();
			return false;
		} finally {
			xdiClient.close();
		}

		return true;

	}

	public XDI3Segment getLinkContractAddress() {
		return linkContractAddress;
	}

	public XDI3Segment getCloudNumber() {
		return cloudNumber;
	}

	public String getRegistryURI() {
		return registryURI;
	}

	public String getCloudEndpointURI() {
		return cloudEndpointURI;
	}

	public void createDefaultLinkContracts() {
		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);
		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		message.setSecretToken(secretToken);
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		message.createSetOperation(XDI3Statement.create("$public"
				+ "[+pendingrequest]" + "$do/" + "$add" + "/" + "$public"
				+ "[+pendingrequest]"));
		message.createSetOperation(XDI3Statement.create("$public"
				+ "[+pendingrequest]" + "$do/" + "$del" + "/" + "$public"
				+ "[+pendingrequest]"));
		message.createSetOperation(XDI3Statement.create("$public"
				+ "[+pendingrequest]" + "$do/" + "$set" + "/" + "$public"
				+ "[+pendingrequest]"));
		message.createSetOperation(XDI3Statement.create("$public"
				+ "[+pendingrequest]"
				+ "$do$if$and/$true/({$from}/$is/{$from})"));

		message.createSetOperation(XDI3Statement.create("$public"
				+ "[+approvedrequest]" + "$do/" + "$add" + "/" + "$public"
				+ "[+approvedrequest]"));
		// message.createSetOperation(XDI3Statement.create("$public"
		// + "[+approvedrequest]" + "$do/" + "$del" + "/" + "$public"
		// + "[+approvedrequest]"));
		message.createSetOperation(XDI3Statement.create("$public"
				+ "[+approvedrequest]" + "$do/" + "$set" + "/" + "$public"
				+ "[+approvedrequest]"));
		message.createSetOperation(XDI3Statement.create("$public"
				+ "[+approvedrequest]"
				+ "$do$if$and/$true/({$from}/$is/{$from})"));

		message.createSetOperation(XDI3Statement.create(cloudNumber + "+friend"
				+ "$do/" + "$all" + "/" + cloudNumber + "+friend"));

		message.createSetOperation(XDI3Statement.create(cloudNumber + "+friend"
				+ "$do$if$or/$true/(" + cloudNumber + "/" + "+friend"
				+ "/{$from}" + ")"));
		message.createSetOperation(XDI3Statement.create(cloudNumber + "+friend"
				+ "$do$if$or/$true/({$from}/$is/" + cloudNumber + ")"));
		message.createSetOperation(XDI3Statement.create(cloudNumber + "+family"
				+ "$do/" + "$all" + "/" + cloudNumber + "+family"));

		message.createSetOperation(XDI3Statement.create(cloudNumber + "+family"
				+ "$do$if$or/$true/(" + cloudNumber + "/" + "+family"
				+ "/{$from}" + ")"));
		message.createSetOperation(XDI3Statement.create(cloudNumber + "+family"
				+ "$do$if$or/$true/({$from}/$is/" + cloudNumber + ")"));
		message.createSetOperation(XDI3Statement.create(cloudNumber
				+ "+coworker" + "$do/" + "$all" + "/" + cloudNumber
				+ "+coworker"));

		message.createSetOperation(XDI3Statement.create(cloudNumber
				+ "+coworker" + "$do$if$or/$true/(" + cloudNumber + "/"
				+ "+coworker" + "/{$from}" + ")"));
		message.createSetOperation(XDI3Statement.create(cloudNumber
				+ "+coworker" + "$do$if$or/$true/({$from}/$is/" + cloudNumber
				+ ")"));

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}

	}

	public void createRelationship(XDI3Segment peerCloudCN,
			XDI3Segment relationship, XDI3Segment reverseRelationship) {
		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope for getting email

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		message.setSecretToken(secretToken);
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		message.createSetOperation(XDI3Statement.create(cloudNumber + "/"
				+ relationship + "/" + peerCloudCN));

		message.createSetOperation(XDI3Statement.create(peerCloudCN + "/"
				+ reverseRelationship + "/" + cloudNumber));

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}
	}

	public void allowAccessToRelationship(XDI3Segment target,
			XDI3Segment mapTarget, XDI3Segment permissionXri,
			XDI3Segment relationship, XDI3Segment reverseRelationship,
			XDI3Segment assignee) {

		PersonalCloud assigneePC = PersonalCloud.open(assignee, cloudNumber,
				XDI3Segment.create("$public$do"), "");
		XDI3Segment assigneeCN = assigneePC.cloudNumber;

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope for creating the link contract for accessing
		// the target

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);
		message.setSecretToken(secretToken);
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(cloudNumber));

		if (mapTarget != null) {
			message.createSetOperation(XDI3Statement.create(target + "/$rep/"
					+ mapTarget));
		}
		message.createSetOperation(XDI3Statement.create(cloudNumber.toString()
				+ relationship.toString() + "$do/" + permissionXri.toString()
				+ "/" + target));

		message.createSetOperation(XDI3Statement.create(cloudNumber.toString()
				+ "/" + relationship + "/" + assigneeCN));

		message.createSetOperation(XDI3Statement.create(assigneeCN + "/"
				+ reverseRelationship + "/" + cloudNumber.toString()));

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}

	}

	public void getPCEntity(XDI3Segment targetAddress,
			XDI3Segment linkContract, PersonalCloud peerCloud) {

		XDIClient xdiClient = new XDIHttpClient(peerCloud.getCloudEndpointURI());

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(cloudNumber, 0);
		message.setLinkContractXri(linkContract);

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(peerCloud
				.getCloudNumber()));

		message.createGetOperation(targetAddress);

		// System.out.println("Message :\n" + messageEnvelope + "\n");
		try {
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// send the message

		MessageResult messageResult;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);
			// System.out.println(messageResult);
			MemoryGraph response = (MemoryGraph) messageResult.getGraph();
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(response,
					System.out);

		} catch (Xdi2ClientException ex) {

			ex.printStackTrace();
		} catch (Exception ex) {

			ex.printStackTrace();
		} finally {
			xdiClient.close();
		}
	}

	/**
	 * 
	 * @param cloudName
	 *            : Desired cloudName for the cloud
	 * @param secretToken
	 *            : Alphanumeric string which will be used as the password to
	 *            login to the cloud
	 * @param CSPName
	 *            : Name of the CSP under which this cloud should be created.
	 *            Valid values are "Neustar", "OwnYourInfo"
	 * @return
	 */
	// public static PersonalCloud create(String cloudName, String secretToken,
	// String CSPName) {
	// CSP csp = null;
	// if (CSPName.equalsIgnoreCase("Neustar")) {
	// csp = new CSPNeustar();
	// } else if (CSPName.equalsIgnoreCase("OwnYourInfo")) {
	// csp = new CSPOwnYourInfo();
	// }
	//
	// if (csp == null) {
	// System.out.println("No valid CSP found for the given CSP name.");
	// return null;
	// }
	//
	// PersonalCloud pc = new PersonalCloud();
	// try {
	// // step 1: Check if Cloud Name available
	//
	// XDI3Segment cloudNumber = CSPClient.checkCloudNameAvailable(csp,
	// cloudName);
	//
	// // step 2: Register Cloud Name
	// if (cloudNumber == null || cloudNumber.toString().length() == 0) {
	//
	// XDI3Segment cloudNumberPeerRootXri = CSPClient
	// .registerCloudName(csp, cloudName);
	//
	// if (cloudNumberPeerRootXri != null
	// && cloudNumberPeerRootXri.toString().length() > 0) {
	// // step 3: Register Cloud with Cloud Number and Shared
	// // Secret
	//
	// String xdiEndpoint = CSPClient.registerCloud(csp,
	// XDI3Segment.create(cloudName), cloudNumber,
	// cloudNumberPeerRootXri, secretToken);
	//
	// if (xdiEndpoint.length() > 0) {
	// // step 4: Register Cloud XDI URL with Cloud Number
	//
	// CSPClient.registerCloudXdiUrl(csp,
	// cloudNumberPeerRootXri, xdiEndpoint);
	// pc.cloudNumber = cloudNumber;
	// pc.cloudEndpointURI = xdiEndpoint;
	// }
	// }
	// }
	// } catch (Exception ex) {
	// ex.printStackTrace();
	// return null;
	// }
	//
	// pc.linkContractAddress = PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT;
	// pc.secretToken = secretToken;
	// pc.senderCloudNumber = pc.cloudNumber;
	// pc.createDefaultLinkContracts();
	// return pc;
	//
	// }

	public String getSessionId() {
		return sessionId;
	}

	public boolean showApprovalForm2(String connectRequest,
			String respondingPartyCloudNumberEncoded, String authToken,
			Hashtable<String, String> formParams,
			Hashtable<String, String> requestedFields) {

		String respondingPartyCloudNumber = null;
		ArrayList<XDI3Segment> getDataFields = new ArrayList<XDI3Segment>();
		try {

			respondingPartyCloudNumber = URLDecoder.decode(
					respondingPartyCloudNumberEncoded, "UTF-8");
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		// System.out.println("Connect Request :\n" + connectRequest);

		System.out.println("respondingPartyCloudNumber : \n"
				+ respondingPartyCloudNumber);

		System.out.println("Auth Token : \n" + authToken);
		this.secretToken = authToken;
		this.linkContractAddress = PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT;
		this.cloudNumber = XDI3Segment.create(respondingPartyCloudNumber);
		this.senderCloudNumber = XDI3Segment.create(respondingPartyCloudNumber);

		MemoryJSONGraphFactory graphFactory = new MemoryJSONGraphFactory();
		String templateOwnerInumber = null;
		try {
			Graph g = graphFactory.parseGraph(connectRequest);
			// get remote cloud number

			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(g,
					System.out);
			ContextNode c = g.getRootContextNode();
			ReadOnlyIterator<ContextNode> allCNodes = c.getAllContextNodes();
			for (ContextNode ci : allCNodes) {
				if (ci.containsContextNode(XDI3SubSegment.create("[$msg]"))) {
					templateOwnerInumber = ci.toString();
					System.out.println(templateOwnerInumber);
					break;
				}
			}
			if (templateOwnerInumber == null) {
				System.out
						.println("No cloudnumber for requestor/template owner");
				return false;
			}
			// get the address of the link contract template
			// $set{$do}

			String lcTemplateAddress = null;

			ReadOnlyIterator<Relation> allRelations = c.getAllRelations();
			for (Relation r : allRelations) {
				if (r.getArcXri().toString().equals("$set{$do}")) {
					lcTemplateAddress = r.getTargetContextNodeXri().toString();
					System.out.println(r.getTargetContextNodeXri());
				} else if (r.getArcXri().toString().equals("$get")) {
					if (r.getTargetContextNodeXri().toString().contains("{$to}")) {
						getDataFields.add(r.getTargetContextNodeXri());
					}
				}

			}
			if (lcTemplateAddress == null) {
				System.out.println("No LC template address provided");
				return false;
			}
//			String meta_link_contract = "{$to}" + templateOwnerInumber
//					+ "{$from}" + templateOwnerInumber + "+registration$do";

			PersonalCloud remoteCloud = PersonalCloud.open(
					XDI3Segment.create(templateOwnerInumber), this.cloudNumber,
					XDI3Segment.create("$public$do"), "");
			ArrayList<XDI3Segment> querySegments = new ArrayList<XDI3Segment>();
//			querySegments.add(XDI3Segment.create(templateOwnerInumber
//					+ "<+name>"));

			querySegments.add(XDI3Segment.create(lcTemplateAddress));

			ArrayList<XDI3Statement> queryStmts = new ArrayList<XDI3Statement>();
			queryStmts.add(XDI3Statement.create(templateOwnerInumber
					+ "/$is$ref/{}"));
			MessageResult responseFromRemoteCloud = null;

			try {
				responseFromRemoteCloud = remoteCloud.sendQueries(
						querySegments, queryStmts, false);
			} catch (Exception ex) {
				return false;
			}
			if (responseFromRemoteCloud == null) {
				return false;
			}

			Graph responseGraph = responseFromRemoteCloud.getGraph();
			ContextNode responseRootContext = responseGraph
					.getRootContextNode();



			ReadOnlyIterator<Relation> getRelations = responseRootContext
					.getAllRelations();
			for (Relation r : getRelations) {
				if (r.getArcXri().toString().equals("$get")) {

					//getDataFields.add(r.getTargetContextNodeXri());
					// System.out.println(r.getTargetContextNodeXri());

				}

			}

			Literal requestingPartyNameLit = responseRootContext
					.getDeepLiteral(XDI3Segment.create(templateOwnerInumber
							+ "<+name>&"));
			Relation requestingPartyCloudnameRel = responseRootContext
					.getDeepRelation(XDI3Segment.create(templateOwnerInumber),
							XDI3Segment.create("$is$ref"));
			if(requestingPartyCloudnameRel == null){
				requestingPartyCloudnameRel = responseRootContext
						.getDeepRelation(XDI3Segment.create(""),
								XDI3Segment.create("$is$ref"));
			}
			String requestingPartyCloudName = requestingPartyCloudnameRel
					.getTargetContextNodeXri().toString();

			querySegments = new ArrayList<XDI3Segment>();
			queryStmts = new ArrayList<XDI3Statement>();
			for (XDI3Segment dataField : getDataFields) {
				String dataFieldStr = dataField.toString();
				if (!dataFieldStr.contains("$is$ref")) {
					dataFieldStr = dataFieldStr.replace("{$to}",
							respondingPartyCloudNumber);

					querySegments.add(XDI3Segment.create(dataFieldStr));
				}
			}
			MessageResult responseFromThisCloud = this.sendQueries(
					querySegments, queryStmts, false);

			Graph responseGraph3 = responseFromThisCloud.getGraph();
			ContextNode responseRootContext3 = responseGraph3
					.getRootContextNode();
			ReadOnlyIterator<Literal> allLiteralsFromResponse = responseRootContext3
					.getAllLiterals();

			for (Literal lit : allLiteralsFromResponse) {

				if(!lit.getContextNode().toString().contains("<+connect>&")){
					requestedFields.put(lit.getContextNode().toString(),
							lit.getLiteralDataString());
				}

			}
			formParams.put("linkContractTemplateAddress", lcTemplateAddress);
			formParams.put("requestingPartyCloudNumber", templateOwnerInumber);
			formParams
					.put("requestingPartyCloudName", requestingPartyCloudName);
		} catch (Xdi2ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}

		return true;
	}

	public String processApprovalForm2(String linkContractTemplateAddress,
			String relyingPartyCloudNumber, String respondingPartyCloudNumber,
			String secrettoken, String[] selectedValues) {
		String xdiResponseValues = new String();

		Graph g1 = MemoryGraphFactory.getInstance().openGraph();
		ArrayList<XDI3Statement> setStatementsForRemote = new ArrayList<XDI3Statement>();
		
		ArrayList<XDI3Statement> setStatements = new ArrayList<XDI3Statement>();
		String isPlusstmt = new String();
		isPlusstmt += respondingPartyCloudNumber;
		isPlusstmt += "$to";
		isPlusstmt += relyingPartyCloudNumber;
		isPlusstmt += "$from";
		isPlusstmt += relyingPartyCloudNumber;
		isPlusstmt += "+registration$do/$is+/";
		isPlusstmt += linkContractTemplateAddress;

		setStatements.add(XDI3Statement.create(isPlusstmt));

		String policyStmt = new String();
		policyStmt += respondingPartyCloudNumber;
		policyStmt += "$to";
		policyStmt += relyingPartyCloudNumber;
		policyStmt += "$from";
		policyStmt += relyingPartyCloudNumber;
		policyStmt += "+registration$do$if$and/$true/({$from}/$is/"
				+ relyingPartyCloudNumber + ")";
		setStatements.add(XDI3Statement.create(policyStmt));
		
		
		policyStmt = new String();
		policyStmt += respondingPartyCloudNumber;
		policyStmt += "$to";
		policyStmt += relyingPartyCloudNumber;
		policyStmt += "$from";
		policyStmt += relyingPartyCloudNumber;
		policyStmt += "+registration$do$if$and/$true/({$msg}<$sig><$valid>&/&/true)";
		setStatements.add(XDI3Statement.create(policyStmt));
		
		

		for (int i = 0; (selectedValues != null) && (i < selectedValues.length); i++) {
			String value = selectedValues[i];
			StringTokenizer st = new StringTokenizer(value, "|");
			String addressPart = st.nextToken();
			String valuePart = st.nextToken();
			xdiResponseValues += addressPart + "/&/" + "\"" + valuePart + "\"";
			g1.setStatement(XDI3Statement.create(addressPart + "/&/" + "\""
					+ valuePart + "\""));
			// strip the last & off
			addressPart = addressPart.substring(0, addressPart.length() - 1);
			String stmt = new String();
			stmt += respondingPartyCloudNumber;
			stmt += "$to";
			stmt += relyingPartyCloudNumber;
			stmt += "$from";
			stmt += relyingPartyCloudNumber;
			stmt += "+registration$do/$get/";
			stmt += addressPart;

			//System.out.println("Set statements :" + stmt);
			setStatements.add(XDI3Statement.create(stmt));
			setStatementsForRemote.add(XDI3Statement.create(stmt));
		}
		if((selectedValues == null) || selectedValues.length == 0){
			String stmt = new String();
			stmt += respondingPartyCloudNumber;
			stmt += "$to";
			stmt += relyingPartyCloudNumber;
			stmt += "$from";
			stmt += relyingPartyCloudNumber;
			stmt += "+registration$do/$get/(";
			stmt += this.cloudNumber + "/$is$ref/" + this.getCloudName(cloudNumber.toString()) + ")";
			setStatementsForRemote.add(XDI3Statement.create(stmt));
		}
		//System.out.println("All Set statements :" + setStatements);
		MessageResult setResponse = this.setXDIStmts(setStatements);
		//System.out.println("Set response : " + setResponse);

		String targetSegment = new String();
		targetSegment += respondingPartyCloudNumber;
		targetSegment += "$to";
		targetSegment += relyingPartyCloudNumber;
		targetSegment += "$from";
		targetSegment += relyingPartyCloudNumber;
		targetSegment += "+registration$do";

		xdiResponseValues += targetSegment + "/$is+/"
				+ linkContractTemplateAddress;
		g1.setStatement(XDI3Statement.create(targetSegment + "/$is+/"
				+ linkContractTemplateAddress));

		// send link contract to the relying party
		// {$from}[@]!:uuid:1+registration$do
		// String lcAddress = "{$to}" + relyingPartyCloudNumber + "{$from}"
		// + relyingPartyCloudNumber + "+registration$do";
		// get cloudname
		ArrayList<XDI3Statement> queryStmts = new ArrayList<XDI3Statement>();
		queryStmts.add(XDI3Statement.create(this.cloudNumber + "/$is$ref/{}"));

		MessageResult cloudNameResp = this.sendQueries(null, queryStmts, false);
		ContextNode responseRootContext = cloudNameResp.getGraph()
				.getRootContextNode();
		if (responseRootContext != null) {
			Relation requestingPartyCloudnameRel = responseRootContext
					.getDeepRelation(this.cloudNumber,
							XDI3Segment.create("$is$ref"));
			if (requestingPartyCloudnameRel != null) {
				String requestingPartyCloudNumberCtx = requestingPartyCloudnameRel
						.getTargetContextNodeXri().toString();
				xdiResponseValues += this.cloudNumber + "/$is$ref/"
						+ requestingPartyCloudNumberCtx + "";
				g1.setStatement(XDI3Statement.create(this.cloudNumber
						+ "/$is$ref/" + requestingPartyCloudNumberCtx + ""));
			}
		}

		Graph g = this.signGraph(
				Signature.getNormalizedSerialization(g1.getRootContextNode()),
				respondingPartyCloudNumber);
		System.out.println("\n\nConnect Response: \n"
				+ g.toString("XDI DISPLAY", null) + "\n\n");
		
//		String meta_link_contract = this.cloudNumber.toString() + "$to" + relyingPartyCloudNumber
//		+ "$from" + relyingPartyCloudNumber + "+registration$do";
		String meta_link_contract = relyingPartyCloudNumber  +"$to$anon$from$public+registration$do";
		
		PersonalCloud remoteCloud = PersonalCloud.open(
		XDI3Segment.create(relyingPartyCloudNumber), this.cloudNumber,
		XDI3Segment.create(meta_link_contract), "");

		MessageResult remoteSetResponse = remoteCloud.setXDIStmts(setStatementsForRemote);
		System.out.println("\n\n Remote Set response for setting LCs using meta LC :\n " + remoteSetResponse + "\n\n");

		return Signature.getNormalizedSerialization(g.getRootContextNode());
	}

	public boolean linkContractExists(String connectRequest) {
		System.out.println("\nChecking if a link contract exists\n");
		boolean result = false;
		MemoryJSONGraphFactory graphFactory = new MemoryJSONGraphFactory();
		String templateOwnerInumber = null;
		String lcTemplateAddress = null;
		try {
			Graph g = graphFactory.parseGraph(connectRequest);
			// get remote cloud number

			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(g,
					System.out);
			ContextNode c = g.getRootContextNode();
			ReadOnlyIterator<ContextNode> allCNodes = c.getAllContextNodes();
			for (ContextNode ci : allCNodes) {
				if (ci.containsContextNode(XDI3SubSegment.create("[$msg]"))) {
					templateOwnerInumber = ci.toString();
					System.out.println(templateOwnerInumber);
					break;
				}
			}
			if (templateOwnerInumber == null) {
				System.out
						.println("No cloudnumber for requestor/template owner");
				return result;
			}
			// get the address of the link contract template
			// $set{$do}

			

			ReadOnlyIterator<Relation> allRelations = c.getAllRelations(); // g.getDeepRelations(XDI3Segment.create(templateOwnerInumber),XDI3Segment.create("$get"));
			for (Relation r : allRelations) {
				if (r.getArcXri().toString().equals("$set{$do}")) {
					lcTemplateAddress = r.getTargetContextNodeXri().toString();
					//System.out.println(r.getTargetContextNodeXri());
				}

			}
			if (lcTemplateAddress == null) {
				System.out.println("No LC template address provided");
				return result;
			}
		} catch (Exception io) {
			io.printStackTrace();
			return result;
		}
		
		//=================================
		PersonalCloud remoteCloud = PersonalCloud.open(
				XDI3Segment.create(templateOwnerInumber), this.cloudNumber,
				XDI3Segment.create("$public$do"), "");
		ArrayList<XDI3Segment> querySegments = new ArrayList<XDI3Segment>();

		querySegments.add(XDI3Segment.create(lcTemplateAddress));

		ArrayList<XDI3Statement> queryStmts = new ArrayList<XDI3Statement>();
		MessageResult responseFromRemoteCloud = null;

		try {
			responseFromRemoteCloud = remoteCloud.sendQueries(
					querySegments, queryStmts, false);
		} catch (Exception ex) {
			return false;
		}
		if (responseFromRemoteCloud == null) {
			return false;
		}

		String lcInstanceAddress = new String();
		lcInstanceAddress += this.cloudNumber;
		lcInstanceAddress += "$to";
		lcInstanceAddress += templateOwnerInumber;
		lcInstanceAddress += "$from";
		lcInstanceAddress += templateOwnerInumber;
		lcInstanceAddress += "+registration$do";
		
		queryStmts = new ArrayList<XDI3Statement>();
		
		Graph responseGraph2 = responseFromRemoteCloud.getGraph();
		ContextNode responseRootContext2 = responseGraph2
				.getRootContextNode();
		ReadOnlyIterator<Relation> getRelations = responseRootContext2
				.getAllRelations();
		for (Relation r : getRelations) {
			if (r.getArcXri().toString().equals("$get")) {
				String lcAccessStmt = lcInstanceAddress + "/$get/";
				String targetContextNode = r.getTargetContextNodeXri().toString();
				targetContextNode = targetContextNode.replace("{$to}", this.cloudNumber.toString());
				lcAccessStmt += targetContextNode;
				queryStmts.add(XDI3Statement.create(lcAccessStmt));
			}

		}
		
		//==============

		

		MessageResult responseFromLocalCloud = this.sendQueries(null,queryStmts,false); 

		if (responseFromLocalCloud != null) {
			Graph responseGraph = responseFromLocalCloud.getGraph();
			ContextNode responseRootContext = responseGraph
					.getRootContextNode();
//			System.out.println("\n\nLink Contract exists check\n\n"
//					+ responseGraph.toString());
			if (!responseGraph.toString().contains("<$false>") && (responseRootContext.getAllLiteralCount() >= queryStmts.size())) {
				result = true;
			}
		}

		return result;
	}

	public String processDisconnectRequest(String requestingParty,
			String respondingParty) {

		String targetSegment = new String();
		targetSegment += this.cloudNumber;
		targetSegment += "$to";
		targetSegment += requestingParty;
		targetSegment += "$from";
		targetSegment += requestingParty;
		targetSegment += "+registration$do";
		MessageResult result = this.delXDIStmts(null,
				XDI3Segment.create(targetSegment));
		System.out.println("Result of delete lc :\n" + result.toString());

		return "<html><body>Deletion of LC was successful!</body></html>";
	}

	public PublicKey getSignaturePublicKey() {
		return signaturePublicKey;
	}

	public void setSignaturePublicKey(PublicKey signaturePublicKey) {
		this.signaturePublicKey = signaturePublicKey;
	}

	public XDI3Segment getCloudName() {
		return cloudName;
	}

	public void setCloudName(XDI3Segment cloudName) {
		this.cloudName = cloudName;
		if(this.secretToken != null && !this.secretToken.isEmpty()) {
			ArrayList <XDI3Statement> isRefStmt = new ArrayList <XDI3Statement>();
			isRefStmt.add(XDI3Statement.create(this.cloudNumber.toString() + "/$is$ref/" + this.cloudName));
			this.setXDIStmts(isRefStmt);
		}
	}

	public XDI3Segment getSenderCloudNumber() {
		return senderCloudNumber;
	}

	public void setSenderCloudNumber(XDI3Segment senderCloudNumber) {
		this.senderCloudNumber = senderCloudNumber;
	}

	public void setCloudNumber(XDI3Segment cloudNumber) {
		this.cloudNumber = cloudNumber;
	}

	public void setCloudEndpointURI(String cloudEndpointURI) {
		this.cloudEndpointURI = cloudEndpointURI;
	}

	public Graph signGraph(String XDIGraph, String address) {

		Signature<?, ?> signature = null;
		Graph graph = null;
		Key k = null;

		XDIReader xdiReader = XDIReaderRegistry.getAuto();
		// parse the graph

		graph = MemoryGraphFactory.getInstance().openGraph();

		try {
			xdiReader.read(graph, new StringReader(XDIGraph));
		} catch (Xdi2ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		ContextNode contextNode = graph.getDeepContextNode(XDI3Segment
				.create(address));
		if (contextNode == null)
			throw new RuntimeException("No context node found at address "
					+ address);

		XDI3Segment privKeyAddress = XDI3Segment
				.create(cloudNumber + "$msg$sig$keypair<$private><$key>&");

		MessageResult result = getXDIStmts(privKeyAddress, true);
		MemoryGraph response = (MemoryGraph) result.getGraph();
		Literal literalValue = response.getDeepLiteral(privKeyAddress);
		String value = (literalValue == null) ? "" : literalValue
				.getLiteralData().toString();
		byte[] key = value.getBytes();
		signature = Signatures.setSignature(contextNode,
				PersonalCloud.DEFAULT_DIGEST_ALGORITHM,
				Integer.parseInt(PersonalCloud.DEFAULT_DIGEST_LENGTH),
				PersonalCloud.DEFAULT_KEY_ALGORITHM,
				Integer.parseInt(PersonalCloud.DEFAULT_KEY_LENGTH));

		if (signature instanceof KeyPairSignature) {

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
					Base64.decodeBase64(key));
			try {
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				k = keyFactory.generatePrivate(keySpec);

				((KeyPairSignature) signature).sign((PrivateKey) k);
				return graph;

			} catch (NoSuchAlgorithmException nalg) {
				nalg.printStackTrace();
			} catch (InvalidKeySpecException invKeySpec) {
				invKeySpec.printStackTrace();
			} catch (GeneralSecurityException gse) {
				gse.printStackTrace();
			}
		}
		return graph;
	}

	public static boolean verifySignature(String XDIGraph, String signedNode,
			String fromCloudnumber) {

		String output = "";
		String output2 = "";
		String stats = "-1";
		String error = null;

		Properties xdiResultWriterParameters = new Properties();

		xdiResultWriterParameters.setProperty(
				XDIWriterRegistry.PARAMETER_IMPLIED, "1");
		xdiResultWriterParameters.setProperty(
				XDIWriterRegistry.PARAMETER_ORDERED, "1");
		xdiResultWriterParameters.setProperty(
				XDIWriterRegistry.PARAMETER_INNER, "1");
		xdiResultWriterParameters.setProperty(
				XDIWriterRegistry.PARAMETER_PRETTY, "1");

		XDIReader xdiReader = XDIReaderRegistry.getAuto();
		XDIWriter xdiResultWriter = XDIWriterRegistry.forFormat("XDI DISPLAY",
				xdiResultWriterParameters);

		Graph graph = null;
		Key k = null;
		Signature<?, ?> signature = null;
		Boolean valid = null;

		long start = System.currentTimeMillis();

		try {

			// parse the graph

			graph = MemoryGraphFactory.getInstance().openGraph();

			xdiReader.read(graph, new StringReader(XDIGraph));

			// find the context node

			ContextNode contextNode = graph.getDeepContextNode(XDI3Segment
					.create(signedNode));
			if (contextNode == null)
				throw new RuntimeException("No context node found at address "
						+ signedNode);
			{

				PersonalCloud fromPC = PersonalCloud.open(
						XDI3Segment.create(fromCloudnumber), "",
						XDI3Segment.create("$public$do"), null);
				XDI3Segment pubKeyAddress = XDI3Segment
						.create(fromCloudnumber + "$msg$sig$keypair<$public><$key>&");

				MessageResult result = fromPC.getXDIStmtsNoSig(pubKeyAddress,
						false);
				MemoryGraph response = (MemoryGraph) result.getGraph();
				Literal literalValue = response.getDeepLiteral(pubKeyAddress);
				String value = (literalValue == null) ? "" : literalValue
						.getLiteralData().toString();

				byte[] key = value.getBytes();
				signature = Signatures.getSignature(contextNode);
				if (signature == null)
					throw new RuntimeException("No signature found at address "
							+ signedNode);

				if (signature instanceof KeyPairSignature) {

					X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
							Base64.decodeBase64(key));
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					k = keyFactory.generatePublic(keySpec);

					valid = Boolean.valueOf(((KeyPairSignature) signature)
							.validate((PublicKey) k));
					fromPC.setSignaturePublicKey((PublicKey) k);
				}
				// else if (signature instanceof SymmetricKeySignature) {
				//
				// k = new SecretKeySpec(Base64.decodeBase64(key), "AES");
				//
				// valid = Boolean.valueOf(((SymmetricKeySignature)
				// signature).validate((SecretKey) k));
				// }
			}

			// output the graph or result

			if (valid == null) {

				StringWriter writer = new StringWriter();

				xdiResultWriter.write(graph, writer);

				output = StringEscapeUtils.escapeHtml(writer.getBuffer()
						.toString());
			} else {

				output = "Valid: " + valid.toString();
			}
		} catch (Exception ex) {

			ex.printStackTrace();
			error = ex.getMessage();
			if (error == null)
				error = ex.getClass().getName();
		}

		if (signature != null) {

			output2 = Signature.getNormalizedSerialization(signature
					.getBaseContextNode());
		}

		long stop = System.currentTimeMillis();
		if (valid != null) {
			return valid.booleanValue();
		} else {
			return false;
		}

	}

	public static boolean verifyMessageSignature(String m) {
		XDIReader xdiReader = XDIReaderRegistry.getAuto();
		Graph graph = null;
		graph = MemoryGraphFactory.getInstance().openGraph();

		try {
			xdiReader.read(graph, new StringReader(m));
		} catch (Xdi2ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ContextNode messageContextNode = null;
		String messageSender = "";
		ContextNode c = graph.getRootContextNode();
		ReadOnlyIterator<ContextNode> allCNodes = c.getAllContextNodes();
		for (ContextNode ci : allCNodes) {
			if (ci.containsContextNode(XDI3SubSegment.create("[$msg]"))) {
				messageSender = ci.toString();

				break;
			}
		}
		ContextNode rootContext = graph.getRootContextNode();
		ReadOnlyIterator<Relation> allRelations = rootContext.getAllRelations();
		for (Relation r : allRelations) {
			if (r.getArcXri().toString().equalsIgnoreCase("$is()")) {
				messageContextNode = r.getContextNode();
				break;
			}
		}

		return PersonalCloud.verifySignature(m, messageContextNode.toString(),
				messageSender);

	}

	public static boolean verifyMessageSignature(Message m) {
		return PersonalCloud.verifySignature(Signature
				.getNormalizedSerialization(m.getContextNode()), m
				.getContextNode().toString(), m.getSender().toString());
	}

	public Message signMessage(Message m) {
		
		
		
		//if there's no secret token, then data can't be signed because private key can't be fetched
		
		if(this.secretToken == null || this.secretToken.isEmpty()){
			return m;
		}
				
		Signature<?, ?> signature = null;

		Key k = null;

		ContextNode contextNode = m.getContextNode();
		if (contextNode == null)
			throw new RuntimeException("No context node found at address "
					+ m.getContextNode());

		XDI3Segment privKeyAddress = XDI3Segment
				.create(cloudNumber + "$msg$sig$keypair<$private><$key>&");

		MessageResult result = getXDIStmtsNoSig(privKeyAddress, false);
		MemoryGraph response = (MemoryGraph) result.getGraph();
		Literal literalValue = response.getDeepLiteral(privKeyAddress);
		String value = (literalValue == null) ? "" : literalValue
				.getLiteralData().toString();
		byte[] key = value.getBytes();
		signature = Signatures.setSignature(contextNode,
				PersonalCloud.DEFAULT_DIGEST_ALGORITHM,
				Integer.parseInt(PersonalCloud.DEFAULT_DIGEST_LENGTH),
				PersonalCloud.DEFAULT_KEY_ALGORITHM,
				Integer.parseInt(PersonalCloud.DEFAULT_KEY_LENGTH));

		if (signature instanceof KeyPairSignature) {

			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
					Base64.decodeBase64(key));
			try {
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				k = keyFactory.generatePrivate(keySpec);

				((KeyPairSignature) signature).sign((PrivateKey) k);
				return m;

			} catch (NoSuchAlgorithmException nalg) {
				nalg.printStackTrace();
			} catch (InvalidKeySpecException invKeySpec) {
				invKeySpec.printStackTrace();
			} catch (GeneralSecurityException gse) {
				gse.printStackTrace();
			}
		}

		return m;
	}
	/**
	 * Saves Email in the Personal Cloud
	 * @param email : The mail object
	 * @param mailId : The unique identifier for the mail object. Used for update.
	 * @return : Unique Id for the mail object for new mails
	 */
	public String saveEmail(PDSEmail email ){
		
		String id = "";
		if(email.getOperation().equals("ADD")){
			id = "!:uuid:"+UUID.randomUUID().toString();
			email.setId(id);
		} else { //UPDATE
			id = email.getId();
		}
		
		ArrayList <XDI3Statement> setStmts = new ArrayList <XDI3Statement>();
		
		
		String setStmt = "";
		
		if(email.getOperation().equals("ADD")){
			setStmt += 	this.cloudNumber.toString();
			setStmt += "[+email]";
			
			setStmt += id ;
			setStmt += "<+date>&/&/\"";
			setStmt += email.getArrivalTime().toString();
			setStmt += "\"";
			
			setStmts.add(XDI3Statement.create(setStmt));
		
			setStmt = "";	
			setStmt += 	this.cloudNumber.toString();
			setStmt += "[+email]";
			setStmt += id ;
			setStmt += "<+sender>&/&/\"";
			setStmt += email.getFrom();
			setStmt += "\"";
			setStmts.add(XDI3Statement.create(setStmt));
	
			setStmt = "";	
			setStmt += 	this.cloudNumber.toString();
			setStmt += "[+email]";
			setStmt += id ;
			setStmt += "<+subject>&/&/\"";
			setStmt += email.getSubject();
			setStmt += "\"";
			setStmts.add(XDI3Statement.create(setStmt));
			
			setStmt = "";	
			setStmt += 	this.cloudNumber.toString();
			setStmt += "[+email]";
			setStmt += id ;
			setStmt += "<+content>&/&/\"";
			setStmt += email.getContent();
			setStmt += "\"";
			setStmts.add(XDI3Statement.create(setStmt));

			
			//build a sender index
			setStmt = "";	
			setStmt += 	this.cloudNumber.toString();
			setStmt += "[+email]" + XdiAbstractMemberUnordered.createDigestArcXri(email.getFrom().toLowerCase(), false)+ "/+from/";
			setStmt += this.cloudNumber.toString(); ;
			setStmt += "[+email]";
			setStmt += id ;
			setStmts.add(XDI3Statement.create(setStmt));
			
		}
		setStmt = "";	
		setStmt += 	this.cloudNumber.toString();
		setStmt += "[+email]";
		setStmt += id ;
		setStmt += "<+priority>&/&/";
		setStmt += email.getPriority();
		setStmts.add(XDI3Statement.create(setStmt));
		
		setStmt = "";	
		setStmt += 	this.cloudNumber.toString();
		setStmt += "[+email]";
		setStmt += id ;
		setStmt += "<+flag>&/&/";
		setStmt += email.getFlag();
		setStmts.add(XDI3Statement.create(setStmt));

		MessageResult result = this.setXDIStmts(setStmts);
		System.out.println("\n Save mail:\n" + result.toString() + "\n");
		
		return id;
	}
	/**
	 * Delete a mail in the Personal Cloud
	 * @param id : UUID of the email which was generated when the email was saved
	 * @return : NONE
	 */
	public void deleteEmail(String id){

		//delete from sender index
		PDSEmail mail = this.getEmail(id);
		if(mail == null){
			return;
		}
		String delStmt = "";	
		delStmt += 	this.cloudNumber.toString();
		delStmt += "[+email]" + XdiAbstractMemberUnordered.createDigestArcXri(mail.getFrom().toLowerCase(), false) ;
		this.deleteNodeTree(XDI3Segment.create(delStmt));

		//delete the email node
		delStmt = 	this.cloudNumber.toString();
		delStmt += "[+email]";
		delStmt += id ;
		this.deleteNodeTree(XDI3Segment.create(delStmt));
	}
	
	public PDSEmail getEmail(String uuid){
		String queryStmt = "";			
		queryStmt += this.cloudNumber.toString();
		queryStmt += "[+email]";
		queryStmt += uuid;
		
		MessageResult result = this.getXDIStmts(XDI3Segment.create(queryStmt), false);
		Graph g = result.getGraph();
		if(g != null && g.getRootContextNode().getAllLiteralCount() > 0) {
			g.toString("XDI DISPLAY",null);
			PDSEmail mail = new PDSEmail();
		
			mail.setId(uuid);
			Literal from = g.getDeepLiteral(XDI3Segment.create(queryStmt+"<+sender>&"));
			if(from != null){
				mail.setFrom(from.getLiteralDataString());
			}
			
			Literal arrTime = g.getDeepLiteral(XDI3Segment.create(queryStmt+"<+date>&"));
			if(arrTime != null){
				mail.setArrivalTime(new Date(arrTime.getLiteralDataString()));
			}
			Literal subject = g.getDeepLiteral(XDI3Segment.create(queryStmt+"<+subject>&"));
			if(subject != null){
				mail.setSubject(subject.getLiteralDataString());
			}
			Literal content = g.getDeepLiteral(XDI3Segment.create(queryStmt+"<+content>&"));
			if(content != null){
				mail.setContent(content.getLiteralDataString());
			}
			return mail;
			
		}
		return null;
	}
	/**
	 * 
	 * @param sender
	 * @return
	 */
	public Vector<PDSEmail> getEmailBySender(String sender){
		Vector<PDSEmail> result = new Vector<PDSEmail>();
		String queryStmt = this.cloudNumber.toString();
		queryStmt += "[+email]";
		queryStmt += XdiAbstractMemberUnordered.createDigestArcXri(sender.toLowerCase(), false);
		
		MessageResult response = this.getXDIStmts(XDI3Segment.create(queryStmt), false);
		Graph g = response.getGraph();
		
		if(g != null && g.getRootContextNode().getAllContextNodeCount() > 0){
			System.out.println(g.toString("XDI DISPLAY", null));	
			ContextNode root = g.getRootContextNode();
			ReadOnlyIterator<Relation> rels = root.getDeepRelations(XDI3Segment.create(queryStmt), XDI3Segment.create("+from"));
			
			for(Relation r : rels){
				XDI3Segment m = r.getTargetContextNodeXri();
				String fqMailId = m.toString();
				String mailUUID = fqMailId.substring(this.cloudNumber.toString().length() + new String("[+email]").length());
				PDSEmail mail = this.getEmail(mailUUID);
				result.add(mail);
			}
		}
		
		return result;
	}
	/**
	 * labels are added as relations
	 * @param mail
	 * @param label
	 */
	public void addEmailLabel(String id , String label){
		
		PDSEmail mail = this.getEmail(id);
		if(mail == null){
			return ;
		}
		ArrayList <XDI3Statement> setStmts = new ArrayList <XDI3Statement>();
		String setStmt = "";	
		setStmt += 	this.cloudNumber.toString();
		setStmt += "[+email]/" + "+" + label + "/";
		setStmt += this.cloudNumber.toString()+ "[+email]" + id ;
		setStmts.add(XDI3Statement.create(setStmt));
		MessageResult result = this.setXDIStmts(setStmts);
	}
	/**
	 * Remove the relation for the label
	 * @param mail
	 * @param label
	 */
	public void removeEmailLabel(String id , String label){
		PDSEmail mail = this.getEmail(id);
		if(mail == null){
			return ;
		}
		ArrayList<XDI3Statement> delStmts = new ArrayList<XDI3Statement>();
		String delStmt = "";	
		delStmt += 	this.cloudNumber.toString();
		delStmt += "[+email]/" + "+" + label + "/";
		delStmt += this.cloudNumber.toString()+ "[+email]" + id ;
		
		delStmts.add(XDI3Statement.create(delStmt));
		this.delXDIStmts(delStmts, null);
		
	}
	/**
	 * 
	 * @param label
	 * @return
	 */
	public Vector<PDSEmail> getEmailByLabel(String label){
		Vector<PDSEmail> result = new Vector<PDSEmail>();
		String queryStmt = this.cloudNumber.toString();
		queryStmt += "[+email]";
		
		MessageResult response = this.getXDIStmts(XDI3Segment.create(queryStmt), false);
		Graph g = response.getGraph();		
		if(g != null && g.getRootContextNode().getAllContextNodeCount() > 0){
			System.out.println(g.toString("XDI DISPLAY", null));	
			ContextNode root = g.getRootContextNode();
			
			ReadOnlyIterator<Relation> rels = root.getDeepRelations(XDI3Segment.create(queryStmt), XDI3Segment.create("+" + label));
			
			for(Relation r : rels){
				XDI3Segment m = r.getTargetContextNodeXri();
				String fqMailId = m.toString();
				String mailUUID = fqMailId.substring(this.cloudNumber.toString().length() + new String("[+email]").length());
				PDSEmail mail = this.getEmail(mailUUID);
				result.add(mail);
			}
		}
		
		return result;
	}
	public String createRespectConnectRequest(String profileName) {
		
//		ProfileInfo profile = this.getProfileInfo(profileName);
//		if(profile == null){
//			return "";
//		}
		ArrayList<XDI3Statement> setStmts = new ArrayList<XDI3Statement>();
		//build and install link contract template
		setStmts.add(XDI3Statement.create( "{$from}" + this.cloudNumber.toString() + "+registration{$do}/$get/{$to}"  + profileName));
		//link contract template policy requiring the requester to be this cloud
		setStmts.add(XDI3Statement.create( "{$from}" + this.cloudNumber.toString() +  "+registration{$do}$if$and/$true/({$from}/$is/" + this.getCloudNumber().toString() + ")"));
		//link contract template policy requiring the request message to be signed
		setStmts.add(XDI3Statement.create("{$from}" + this.cloudNumber.toString() +  "+registration{$do}$if$and/$true/({$msg}<$sig><$valid>&/&/true)"));
		
		//public link contract for link contract template
		
		setStmts.add(XDI3Statement.create(cloudNumber.toString()  +"$to$anon$from$public$do" +"/" +  "$get" + "/" +  "{$from}" + this.cloudNumber.toString() + "+registration{$do}")); 

		//public link contract for link contract template
		
		//setStmts.add(XDI3Statement.create(cloudNumber.toString()  +"$to$anon$from$public+registration$do" +"/" +  "$set{$do}/"  +"{$to}$to" + this.cloudNumber.toString() +  "$from" + this.cloudNumber.toString() + "+registration$do")); 
		setStmts.add(XDI3Statement.create(cloudNumber.toString()  +"$to$anon$from$public+registration$do" +"/" +  "$all/"));

		//meta link contract for the link contract template
		setStmts.add(XDI3Statement.create( "{$to}" + this.cloudNumber.toString() + "$from" + this.cloudNumber.toString() + "+registration$do/$set{$do}/" + "{$from}" +  this.cloudNumber.toString() +  "+registration{$do}"));
		// TBD : meta link contract template policy requiring the instance message to be signed
//		setStmts.add(XDI3Statement.create( "{$to}" + this.cloudNumber.toString() + "$from" + this.cloudNumber.toString() + "+registration$do$if/$true/({$msg}<$sig><$valid>&/&/true)"));
		
		this.setXDIStmts(setStmts);
		
		//create connect request message
		MemoryGraph connectReqGraph = MemoryGraphFactory.getInstance().openGraph();
		XDI3Statement stmt = XDI3Statement.create(this.cloudNumber.toString() + "[$msg]#0$do/$get/({$to}/$is$ref/{})");
		connectReqGraph.setStatement(stmt);
		stmt = XDI3Statement.create(this.cloudNumber.toString() + "[$msg]#0/$is()/{$to}");
		connectReqGraph.setStatement(stmt);
		stmt = XDI3Statement.create(this.cloudNumber.toString() + "[$msg]#0/$is+/$connect[$v]#0$xdi[$v]#1$msg");
		connectReqGraph.setStatement(stmt);
		stmt = XDI3Statement.create(this.cloudNumber.toString() + "[$msg]#0$do/$get/{$to}" +  profileName );
		connectReqGraph.setStatement(stmt);
		stmt = XDI3Statement.create(this.cloudNumber.toString() + "[$msg]#0$do/$set{$do}/" + "{$from}" + this.cloudNumber.toString() +  "+registration{$do}");
		connectReqGraph.setStatement(stmt);
		
//		MessageEnvelope messageEnvelope = new MessageEnvelope();
//		Message message = messageEnvelope.createMessage(this.cloudNumber, 0);
//		message.setToPeerRootXri(XDI3SubSegment.create("{$to}"));
//		message.setMessageType(XDI3Segment.create("$connect[$v]#0$xdi[$v]#1$msg"));
//		message.createGetOperation(XDI3Statement.create("({$to}/$is$ref/{})"));
		Graph signedGraph = this.signGraph(connectReqGraph.toString(), this.cloudNumber.toString() + "[$msg]#0");
		
		return signedGraph.toString("XDI/JSON",null);
	}
	
	public void getListofLCs(Hashtable<String,String> youHaveGivenToSomeone, Hashtable<String,String> someoneGaveItToYou){
		Graph g = this.getWholeGraph();
		ContextNode root = g.getRootContextNode();
		ReadOnlyIterator<Relation> allRelations = root.getAllRelations();
		for(Relation r : allRelations){
			String arcName = r.getArcXri().toString();
			if(arcName.equals("$get") || arcName.equals("$set") ){
				String LCAddress = r.getContextNode().toString();
				if (LCAddress.contains("+registration$do") && LCAddress.contains("$to") && LCAddress.contains("$from")) {
					
					String authorizingParty = LCAddress.substring(0, LCAddress.indexOf("$to"));
					String requestingParty = LCAddress.substring(LCAddress.indexOf("$to") + 3, LCAddress.indexOf("$from"));
					if(authorizingParty.equalsIgnoreCase(this.cloudNumber.toString())){
						if(requestingParty != null && !requestingParty.isEmpty() && youHaveGivenToSomeone.get(requestingParty) == null){
							youHaveGivenToSomeone.put(requestingParty, getCloudName(requestingParty));
						}
					} else {
						if(authorizingParty != null && !authorizingParty.isEmpty() && someoneGaveItToYou.get(authorizingParty) == null) {
							someoneGaveItToYou.put(authorizingParty, getCloudName(authorizingParty));
						}
					}
				}
			}
		}
	}
	public String getCloudName(String cloudNumber){
		
		PersonalCloud remoteCloud = PersonalCloud.open(
				XDI3Segment.create(cloudNumber), this.cloudNumber,
				XDI3Segment.create("$public$do"), "");
		ArrayList<XDI3Statement> queryStmts = new ArrayList<XDI3Statement>();
		queryStmts.add(XDI3Statement.create(cloudNumber
				+ "/$is$ref/{}"));
		MessageResult responseFromRemoteCloud = null;

		try {
			responseFromRemoteCloud = remoteCloud.sendQueries(
					null, queryStmts, false);
		} catch (Exception ex) {
			return "";
		}
		if (responseFromRemoteCloud == null) {
			return "";
		}

		Graph responseGraph = responseFromRemoteCloud.getGraph();
		ContextNode responseRootContext = responseGraph
				.getRootContextNode();
		Relation requestingPartyCloudnameRel = responseRootContext
				.getDeepRelation(XDI3Segment.create(cloudNumber),
						XDI3Segment.create("$is$ref"));
		if(requestingPartyCloudnameRel == null){
			requestingPartyCloudnameRel = responseRootContext
					.getDeepRelation(XDI3Segment.create(""),
							XDI3Segment.create("$is$ref"));
		}
		String cloudName = requestingPartyCloudnameRel
				.getTargetContextNodeXri().toString();

		return cloudName;
	}

}

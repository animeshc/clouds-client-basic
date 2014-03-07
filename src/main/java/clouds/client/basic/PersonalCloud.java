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
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;
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
	

	public static String DEFAULT_DIGEST_ALGORITHM = "sha";
	public static String DEFAULT_DIGEST_LENGTH = "256";
	public static String DEFAULT_KEY_ALGORITHM = "rsa";
	public static String DEFAULT_KEY_LENGTH = "2048";

	

	/*
	 * factory methods for opening personal clouds
	 */

	/**
	 * 
	 * @param cloudNameOrCloudNumber : Identifier for the cloud that is being opened.
	 * @param secretToken : Plain text of the secret token for the Personal Cloud
	 * @param linkContractAddress : Root link contract address - $do 
	 * @param regURI : Registry URI if not already set in the DEFAULT_REGISTRY_URI variable or different from DEFAULT_REGISTRY_URI
	 * @param session : A session identifier for a long-lived session. The session identifier can be uesd as an alternative to the secret token.
	 * 					This feature is not implemented yet.
	 * @return : A PersonalCloud instance or null if the secret token is wrong.
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
				XDI3Statement getName = XDI3Statement.create(pc.cloudNumber
						+ "/$is$ref/{}");
				if(pc.getXDIStmtsNoSig(getName, false) == null){
					return null;
				}

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

	/**
	 * An utility method where the session token field is not provided. 
	 * @param cloudNameOrCloudNumber : Identifier for the cloud that is being opened.
	 * @param secretToken : Plain text of the secret token for the Personal Cloud
	 * @param linkContractAddress : Root link contract address - $do 
	 * @param regURI : Registry URI if not already set in the DEFAULT_REGISTRY_URI variable or different from DEFAULT_REGISTRY_URI
	 * @param session : A session identifier for a long-lived session. The session identifier can be uesd as an alternative to the secret token.
	 * 					This feature is not implemented yet.
	 * @return : A PersonalCloud instance or null if the secret token is wrong.
	 */
	public static PersonalCloud open(XDI3Segment cloudNameOrCloudNumber,
			String secretToken, XDI3Segment linkContractAddress, String regURI) {
		return PersonalCloud.open(cloudNameOrCloudNumber, secretToken,
				linkContractAddress, regURI, null);
	}

	/**
	 * @return A string with the cloudnumber , Registry URI and Cloud Endpoint URI for this object
	 */
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
	 * Open a peer cloud i.e. someone else's cloud, other than one's own
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
	
	/**
	 * 
	 * @param cloudName : Identifier whose cloudnumber is being searched. This allows for cloudname as the search key for now.
	 * 					  
	 * @param regURI
	 * @return
	 */

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

	/**
	 * 
	 * @return : The complete XDI graph of the Personal Cloud object. This queries the root of the graph and returns the subgraph as a set of XDI statements.
	 */
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

	/**
	 * Create a new profile
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
//		profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString() + "[+profile]" + uuid
//						+ "<+flag+all+event+notification>&/&/" + "true"));
//		profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString() + "[+profile]" + uuid
//				+ "<+flag+major+event+notification>&/&/" + "false" ));
//		profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString() + "[+profile]" + uuid
//				+ "<+filter+event+notification>&/&/" + "false" + ""));
		
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
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString()  +  "+profile+default" + "/$rep/" + cloudNumber.toString() + "[+profile]" + uuid 
					));
			//create a public link contract to the named context so that the context is readable to everyone
			profileXDIStmts.add(XDI3Statement.create(cloudNumber.toString()  +"$to$anon$from$public$do" +"/" +  "$get" + "/" +   cloudNumber.toString()  +  "+profile+default" 
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

		if(!relativeXDIAddress.startsWith("+profile")){
			relativeXDIAddress = "+profile" + relativeXDIAddress;
		}
		
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
	/**
	 * Saves a map of name-value pairs in the graph. The names are XDI addresses of literal value nodes and the values are string , integer or a boolean
	 * @param nameValuePairs
	 * @return
	 */
	public boolean saveNameValuePairs(Hashtable<String,Object> nameValuePairs){
		
		if(nameValuePairs == null || nameValuePairs.size() == 0 ){
			return true;
		}
		ArrayList<XDI3Statement> setStmts = new ArrayList<XDI3Statement>();
		
		Set<String> keys = nameValuePairs.keySet();
		for ( String key :  keys){
			
			Object value =  nameValuePairs.get(key);
			
			if(value instanceof String ){
				setStmts.add(XDI3Statement.create(key +"/&/\"" + value + "\""));
			} else if (value instanceof Integer) {
				Integer i = (Integer)value;
				setStmts.add(XDI3Statement.create(key +"/&/" + i.intValue() ));
			} else if (value instanceof Double) {
				Double d = (Double)value;
				setStmts.add(XDI3Statement.create(key +"/&/" + d.doubleValue() ));
			} else if (value instanceof Boolean) {
				Boolean b = (Boolean)value;
				setStmts.add(XDI3Statement.create(key +"/&/" + b.booleanValue() ));
			}
		}
		this.setXDIStmts(setStmts);
		return true;
	}
	
	public String getStringLiteral(String address){
		XDI3Segment target = XDI3Segment.create(address);
		MessageResult result = this.getXDIStmts(target, false);
		MemoryGraph response = (MemoryGraph) result.getGraph();
		Literal literalNode = response.getDeepLiteral(XDI3Segment
				.create(address));
		if(literalNode == null || literalNode
				.getLiteralData() == null){
			return null;
		}
		return literalNode
				.getLiteralData().toString();
	}
	public Double getNumberLiteral(String address){
		XDI3Segment target = XDI3Segment.create(address);
		MessageResult result = this.getXDIStmts(target, false);
		MemoryGraph response = (MemoryGraph) result.getGraph();
		Literal literalNode = response.getDeepLiteral(XDI3Segment
				.create(address));
		if(literalNode == null || literalNode
				.getLiteralData() == null){
			return null;
		}
		return  new Double(literalNode
				.getLiteralData().toString());
	}
	public Boolean getBooleanLiteral(String address){
		XDI3Segment target = XDI3Segment.create(address);
		MessageResult result = this.getXDIStmts(target, false);
		MemoryGraph response = (MemoryGraph) result.getGraph();
		Literal literalNode = response.getDeepLiteral(XDI3Segment
				.create(address));
		if(literalNode == null || literalNode
				.getLiteralData() == null){
			return null;
		}
		return  new Boolean(literalNode
				.getLiteralData().toString());
	}
	
	public boolean deleteLiteralValue(String address){
		ArrayList<XDI3Statement> setNullStmt = new ArrayList<XDI3Statement>();
		setNullStmt.add(XDI3Statement.create(address + "/&/" + "null"));
		MessageResult result = this.setXDIStmts(setNullStmt);
		if(result.getGraph().getRootContextNode().getAllContextNodeCount() != 0){
			return false;
		}
		return true;
	}
	/**
	 * 
	 * @param XDIStmts
	 * @return
	 */
	public MessageResult setXDIStmts(ArrayList<XDI3Statement> XDIStmts) {

		// prepare XDI client

		XDIClient xdiClient = new XDIHttpClient(cloudEndpointURI);

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(this.senderCloudNumber, 0);
		message.setLinkContractXri(linkContractAddress);

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(this.cloudNumber));

		if (XDIStmts != null && XDIStmts.size() > 0) {
			message.createSetOperation(XDIStmts.iterator());
		}

		if (secretToken != null) {
			message.setSecretToken(secretToken);
			message = this.signMessage(message);
		}
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
	
	/**
	 * 
	 * @param peerCloud
	 * @param XDIStmts
	 * @param targetEndpointURI
	 * @return
	 */
	public MessageResult setXDIStmtsToPeerCloud(PersonalCloud peerCloud , ArrayList<XDI3Statement> XDIStmts , String targetEndpointURI) {
		// prepare XDI client

		XDIClient xdiClient = null ;
		if(targetEndpointURI == null || targetEndpointURI.isEmpty()) {
			xdiClient = new XDIHttpClient(cloudEndpointURI);
		} else {
			xdiClient = new XDIHttpClient(targetEndpointURI);
		}

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(this.cloudNumber, 0);
		message.setLinkContractXri(peerCloud.getLinkContractAddress());

		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(peerCloud.getCloudNumber()));

		if (XDIStmts != null && XDIStmts.size() > 0) {
			message.createSetOperation(XDIStmts.iterator());
		}
		
		message = this.signMessage(message);
		
		System.out.println();
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
	
	/**
	 * 
	 * @param XDIStmts
	 * @param target
	 * @return
	 */

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

	/**
	 * 
	 * @param peerCloud
	 * @param queries
	 * @param queryStmts
	 * @param targetEndpointURI
	 * @return
	 */
	public MessageResult sendQueriesToPeerCloud(PersonalCloud peerCloud , ArrayList<XDI3Segment> queries,
			ArrayList<XDI3Statement> queryStmts, String targetEndpointURI ){
		
		boolean isDeref = false;
		XDIClient xdiClient = null;
		if(targetEndpointURI == null || targetEndpointURI.isEmpty()){
			xdiClient = new XDIHttpClient(peerCloud.cloudEndpointURI);
		} else {
			xdiClient = new XDIHttpClient(targetEndpointURI);
		}

		// prepare message envelope

		MessageEnvelope messageEnvelope = new MessageEnvelope();
		Message message = messageEnvelope.createMessage(this.cloudNumber, 0);
		message.setLinkContractXri(peerCloud.getLinkContractAddress());
		
		message.setToPeerRootXri(XdiPeerRoot.createPeerRootArcXri(peerCloud.getCloudNumber()));

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

		//sign the message
		message = this.signMessage(message);
		try {
			System.out.println("\nbegin message being sent to peer cloud \n");
			XDIWriterRegistry.forFormat("XDI DISPLAY", null).write(
					messageEnvelope.getGraph(), System.out);
			System.out.println("\nend of message being sent to peer cloud \n");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// send the message

		MessageResult messageResult = null;

		try {

			messageResult = xdiClient.send(messageEnvelope, null);

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
	
	/**
	 * 
	 * @param queries
	 * @param queryStmts
	 * @param isDeref
	 * @return
	 */
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

	/**
	 * 
	 * @param query
	 * @param isDeref
	 * @return
	 */
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

	/**
	 * 
	 * @param query
	 * @param isDeref
	 * @param withSignature
	 * @return
	 */
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
	
	/**
	 * 
	 * @param query
	 * @param isDeref
	 * @param withSignature
	 * @return
	 */
	public MessageEnvelope buildMessage(XDI3Statement query, boolean isDeref,
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

	/**
	 * 
	 * @param query
	 * @param isDeref
	 * @return
	 */
	protected MessageResult getXDIStmtsNoSig(XDI3Segment query, boolean isDeref) {

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

	/**
	 * 
	 * @param query
	 * @param isDeref
	 * @return
	 */
	protected MessageResult getXDIStmtsNoSig(XDI3Statement query, boolean isDeref) {

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
	/**
	 * cloudName : identifier for the person/entity that's being added, ex. =alice
	 * groupName : identifier for the group that's being added, ex. +friend
	 * @return : if the operation is successful return true, else return false
	 */
	public boolean addEntityToGroup(String cloudName , String groupName){
		PersonalCloud entityCloud = PersonalCloud.open(XDI3Segment.create(cloudName), this.getCloudNumber(), XDI3Segment.create("$public$do"), "");
		if(entityCloud == null){
			return false;
		}
		
		ArrayList<XDI3Statement> XDIStmts = new ArrayList<XDI3Statement>();
		XDIStmts.add(XDI3Statement.create(this.cloudNumber + "+group" + groupName + "/()/" + entityCloud.getCloudNumber()));
		XDIStmts.add(XDI3Statement.create( this.cloudNumber +  "/" + groupName + "/" + this.cloudNumber + "+group" + groupName + entityCloud.getCloudNumber()));
		MessageResult result = this.setXDIStmts(XDIStmts);
		if(result == null){
			return false;
		} else {
			return true;
		}
		 
	}
	/**
	 * 
	 * @param groupName : XDI name for the group , ex : +friend , +family , +special+friend
	 * @return
	 */
	public boolean addNamedGroup(String groupName){
		
		ArrayList<XDI3Statement> XDIStmts = new ArrayList<XDI3Statement>();
		XDIStmts.add(XDI3Statement.create(this.cloudNumber + "/()/" + "+group" + groupName));
		XDIStmts.add(XDI3Statement.create( this.cloudNumber +  "/" + "+group" + groupName + "/" + this.cloudNumber + "+group" + groupName ));		
		MessageResult result = this.setXDIStmts(XDIStmts);
		if(result == null){
			return false;
		} else {
			return true;
		}
	}
	/**
	 * 
	 * @param contextName
	 * @return
	 */
	public boolean addNamedContext(String contextName){
		
		ArrayList<XDI3Statement> XDIStmts = new ArrayList<XDI3Statement>();
		XDIStmts.add(XDI3Statement.create(this.cloudNumber + "/()/" + "+context" + contextName));
		MessageResult result = this.setXDIStmts(XDIStmts);
		if(result == null){
			return false;
		} else {
			return true;
		}
	}
	
	/**
	 * ex : (cloudnumber/+friend)+group+friend$do/$get/cloudnumber+context+soccer , (cloudnumber/+family)+group+family$do/$get/cloudnumber+context+home
	 * @param contextName :
	 * @param groupName : relationship
	 * @param cloudNameOrNumber : the entity that access is being given to
	 * @return
	 */
	public boolean shareContextWithGroupOrIndividual(String contextName , String groupName,  String cloudNameOrNumber){
		
		String cloudNumber = cloudNameOrNumber;
		
		if(cloudNameOrNumber != null && !cloudNameOrNumber.isEmpty() && (cloudNameOrNumber.startsWith("=") || cloudNameOrNumber.startsWith("@"))){
			PersonalCloud entityCloud = PersonalCloud.open(XDI3Segment.create(cloudNameOrNumber), this.getCloudNumber(), XDI3Segment.create("$public$do"), "");
			if(entityCloud == null){
				return false;
			}
			cloudNumber = entityCloud.getCloudNumber().toString();
		}
			
		ArrayList<XDI3Statement> XDIStmts = new ArrayList<XDI3Statement>();
		XDI3Statement LCStmt = XDI3Statement.create("(" + this.cloudNumber + "/" + groupName + ")" +  "$do/$get/" + this.cloudNumber + "+context" + contextName);
		
		XDI3Statement LCStmtPolicy = null;
		XDI3Statement LCStmt2 = null;
		if(cloudNameOrNumber == null || cloudNameOrNumber.isEmpty()){
			LCStmtPolicy = XDI3Statement.create("(" + this.cloudNumber + "/" + groupName + ")" +  "$do$if$or/$true/(" + this.cloudNumber + "/" + groupName + "/{$from})");
			
		} else {
			LCStmtPolicy = XDI3Statement.create("(" + this.cloudNumber + "/" + groupName + ")" +  "$do$if$or/$true/(" + "{$from}" + "/" + "$is" + "/" + cloudNumber + ")");
			LCStmt2 = XDI3Statement.create( this.cloudNumber +  "$to" + cloudNumber + "$from+registration$do/$get/" + this.cloudNumber + "+context" + contextName);
		}
		XDIStmts.add(LCStmt);
		XDIStmts.add(LCStmt2);
		XDIStmts.add(LCStmtPolicy);
		MessageResult result = this.setXDIStmts(XDIStmts);
		
		if(result == null){
			return false;
		} else {
			return true;
		}
	}

}

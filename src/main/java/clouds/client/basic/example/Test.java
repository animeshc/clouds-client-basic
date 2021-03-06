package clouds.client.basic.example;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import xdi2.core.Graph;
import xdi2.core.constants.XDILinkContractConstants;
import xdi2.core.xri3.XDI3Segment;
import clouds.client.basic.PDSXElement;
import clouds.client.basic.PDSXElementTemplate;
import clouds.client.basic.PDSXEntity;
import clouds.client.basic.PersonalCloud;
import clouds.client.basic.ProfileInfo;

public class Test {

	public static void testSaveProfile(String name , String passwd, String email , String phone) {
		// open my own personal cloud

		PersonalCloud cloud = PersonalCloud.open(XDI3Segment.create(name), passwd, PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT,"","");

		// store my profile info

		ProfileInfo profileInfo = new ProfileInfo();
		profileInfo.setEmail(email);
		profileInfo.setPhone(phone);

		//cloud.saveProfileInfo(profileInfo);		
	}
	public static void testMyOwnPersonalCloud(String name , String passwd) {

		// open my own personal cloud

		PersonalCloud cloud = PersonalCloud.open(XDI3Segment.create(name), passwd, PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT,"","");

		// store my profile info

//		ProfileInfo profileInfo = new ProfileInfo();
//		profileInfo.setEmail("markus.sabadello@gmail.com");
//		profileInfo.setPhone("+43 664 3154848");
//
//		cloud.saveProfileInfo(profileInfo);

		// store other people's contact info

//		ContactInfo contactInfoAnimesh = new ContactInfo();
//		contactInfoAnimesh.setCloudName(XDI3Segment.create("=animesh"));
//		contactInfoAnimesh.setEmail("animesh.chowdhury@neustar.biz");
//
//		cloud.saveContactInfo(XDI3Segment.create("=animesh"), contactInfoAnimesh);

		// look up someone's contact info

//		ContactInfo contactInfoWilliam = cloud.findContactInfoById("william");
		cloud.getWholeGraph();
	}

	public static void testOnOtherPersonalCloudWithDiscovery(String name) {

		PersonalCloud pc1 = PersonalCloud.open(
				 XDI3Segment.create("=dev.animesh"), "animesh123",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");
		// open someone else's personal cloud
		 PersonalCloud pc_markus = PersonalCloud.open(
		 XDI3Segment.create(name),pc1.getCloudNumber(),
		 XDI3Segment.create(pc1.getCloudNumber().toString() +"$do"), "");
		 

	}
	
	
	public static void testAccessGranting(){
		PersonalCloud pc1 = PersonalCloud.open(
				 XDI3Segment.create("=dev.animesh"), "animesh123",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");

				ProfileInfo pc1Prof = new ProfileInfo();
				 pc1Prof.setEmail("animesh.chowdhury@neustar.biz");
				 pc1Prof.setPhone("1-240-620-4205");
				 pc1.createNewProfile(pc1Prof);
				pc1.allowAccess(pc1Prof, XDILinkContractConstants.XRI_S_GET,
				XDI3Segment.create("=markus"));
				Graph pc1Graph = pc1.getWholeGraph();
				
				// open someone else's personal cloud
//				 PersonalCloud pc_markus = PersonalCloud.open(
//				 XDI3Segment.create("=markus"),pc1.getCloudNumber(),
//				 XDI3Segment.create(pc1.getCloudNumber().toString() +"$do"), "");				
//				
//				System.out.println(pc_markus.getProfileInfo().getPhone());


				// pc1.allowAccess(todoList, XDILinkContractConstants.XRI_S_GET,
				// XDI3Segment.create("=markus"));


	}
	public static void testAccessRemoval(){
		
		PersonalCloud pc1 = PersonalCloud.open(
				 XDI3Segment.create("=dev.animesh"), "animesh123",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");

				ProfileInfo pc1Prof = new ProfileInfo();
				 pc1.removeAccess( null,XDI3Segment.create("=markus"));
				 Graph pc1Graph = pc1.getWholeGraph();		
		
	}
	public static void testSharedDataAccess() {
		PersonalCloud pc1 = PersonalCloud.open(
				 XDI3Segment.create("=markus"), "markus",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");
		PersonalCloud pc2 = PersonalCloud.open(
				 XDI3Segment.create("=dev.animesh"), pc1.getCloudNumber(),
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "");
		String linkContract = pc1.getCloudNumber().toString() + "$do";
		pc2.setLinkContractAddress(XDI3Segment.create(linkContract));
		//System.out.println("Shared PC's phone:" + pc2.getProfileInfo().getPhone());
		
	}
	
	public static void testPDSXOps(){
		PersonalCloud pc1 = PersonalCloud.open(
				 XDI3Segment.create("=dev.animesh"), "animesh123",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");
		PDSXElementTemplate profileNameTemplate = new PDSXElementTemplate("myProfileName","Name", true, "text", "What is your name?");
		PDSXElementTemplate profileEmailTemplate = new PDSXElementTemplate("myProfileEmail","Email", true, "text", "Your home email address");
		PDSXEntity.addTemplate("Person",profileNameTemplate);
		PDSXEntity.addTemplate("Person",profileEmailTemplate);
		
		PDSXEntity ako = PDSXEntity.get(pc1, "Person", "ako");
		
		PDSXEntity alexContact = new PDSXEntity("Person", "Contact information for a person", "ako");	
		
		PDSXElement alexName = new PDSXElement(alexContact, profileNameTemplate, "Alex Olson");
		PDSXElement alexEmail = new PDSXElement(alexContact, profileEmailTemplate, "ako@nynetx.com");
		
		alexContact.save(pc1);
		
		PDSXEntity markusContact = new PDSXEntity("Person", "Contact information for a person", "markus");		
		PDSXElement markusName = new PDSXElement(markusContact, profileNameTemplate, "Markus Sabadello");
		PDSXElement markusEmail = new PDSXElement(markusContact, profileEmailTemplate, "markus.sabadello.@gmail.com");
		
		markusContact.save(pc1);
		
		PDSXEntity person1 = PDSXEntity.get(pc1, "Person", "ako");
		System.out.println(person1.toString());
		//PDSXEntity.get(pc1, "Person", 1);
	}
	
	public static void testRelationships(){
		PersonalCloud pc_animesh = PersonalCloud.open(
				 XDI3Segment.create("=dev.animesh3"), "animesh123",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");
		PersonalCloud pc_markus = PersonalCloud.open(
				 XDI3Segment.create("=markus"),pc_animesh.getCloudNumber(),
				 XDI3Segment.create("$public$do"), "");
		//pc_animesh.createRelationship(pc_markus, XDI3Segment.create("+friend"),XDI3Segment.create("+friend"));
		
//		PDSXElementTemplate profileNameTemplate = new PDSXElementTemplate("myProfileName","Name", true, "text", "What is your name?");
//		PDSXElementTemplate profileEmailTemplate = new PDSXElementTemplate("myProfileEmail","Email", true, "text", "Your home email address");
//		PDSXEntity.addTemplate("Person",profileNameTemplate);
//		PDSXEntity.addTemplate("Person",profileEmailTemplate);
//		
//		
//		PDSXEntity trungContact = new PDSXEntity("Person", "Contact information for a person", "trung");	
//		
//		PDSXElement trungName = new PDSXElement(trungContact, profileNameTemplate, "Trung Tran");
//		PDSXElement trungEmail = new PDSXElement(trungContact, profileEmailTemplate, "trung.tran@neustar.biz");
//		trungContact.save(pc_animesh);
//		
//		PDSXEntity trung = PDSXEntity.get(pc_animesh, "Person", "trung");
		//pc_animesh.allowAccessToRelationship(XDI3Segment.create(pc_animesh.getCloudNumber().toString() + "<+email>&"),null,XDI3Segment.create("$get"), XDI3Segment.create("+friend"),XDI3Segment.create("+friend"),XDI3Segment.create("=markus"));
		//pc_animesh.allowAccessToRelationship(XDI3Segment.create("=animesh" + "<+personal_email>&"),XDI3Segment.create(pc_animesh.getCloudNumber().toString() + "<+email>&"),XDI3Segment.create("$get"), XDI3Segment.create("+friend"),XDI3Segment.create("+friend"),XDI3Segment.create("=markus"));
		
		pc_animesh.getWholeGraph();
		PersonalCloud pc_markus2 = PersonalCloud.open(
				 XDI3Segment.create("=markus"), "markus",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");
		
		PersonalCloud pc_animesh2 = PersonalCloud.open(
				 XDI3Segment.create("=dev.animesh3"),pc_markus2.getCloudNumber(),
				 XDI3Segment.create("$public$do"), "");
		//pc_animesh2.getPCEntity(XDI3Segment.create(pc_animesh2.getCloudNumber().toString() + "[+Person]*trung"), XDI3Segment.create(pc_animesh2.getCloudNumber().toString() + "+friend$do" ));
		//pc_markus.getPCEntity(XDI3Segment.create(pc_animesh2.getCloudNumber().toString() + "<+email>&"), XDI3Segment.create(pc_animesh2.getCloudNumber().toString() + "+friend$do" ),pc_animesh2);
		
		
	}
	public static void testDeleteNode(){
		PersonalCloud pc_animesh = PersonalCloud.open(
				 XDI3Segment.create("=dev.animesh"), "animesh123",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");
		pc_animesh.deleteNodeTree(XDI3Segment.create("[=]!:uuid:0c5525d0-2744-ecf4-0c55-25d02744ecf4+friend"));
		pc_animesh.deleteNodeTree(XDI3Segment.create("[=]!:uuid:0c5525d0-2744-ecf4-0c55-25d02744ecf4+family"));
		pc_animesh.deleteNodeTree(XDI3Segment.create("[=]!:uuid:0c5525d0-2744-ecf4-0c55-25d02744ecf4+coworker"));
		pc_animesh.deleteNodeTree(XDI3Segment.create("[=]!:uuid:0c5525d0-2744-ecf4-0c55-25d02744ecf4[+Person]*ako"));
		pc_animesh.deleteNodeTree(XDI3Segment.create("[=]!:uuid:0c5525d0-2744-ecf4-0c55-25d02744ecf4[+Person]*markus"));
		pc_animesh.deleteNodeTree(XDI3Segment.create("[=]!:uuid:0c5525d0-2744-ecf4-0c55-25d02744ecf4[+Person]*les"));
	}
	public static void testAddNamedGroup(){
		PersonalCloud pc_test1 = PersonalCloud.open(
				 XDI3Segment.create("=neustar.test1"), "mysecret",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");
		pc_test1.addNamedGroup("+friend");
		pc_test1.addNamedGroup("+family");
	}
	public static void testAddNamedContext(){
		PersonalCloud pc_test1 = PersonalCloud.open(
				 XDI3Segment.create("=neustar.test1"), "mysecret",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");
		pc_test1.addNamedContext("+soccer");
		pc_test1.addNamedContext("+iiw");
	}
	public static void testAddEntityToNamedGroup(){
		PersonalCloud pc_test1 = PersonalCloud.open(
				 XDI3Segment.create("=neustar.test1"), "mysecret",
				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");
		pc_test1.addNamedGroup("+friend");
		
		pc_test1.addEntityToGroup("=neustar.test2", "+friend");
		
	}
	public static void main(String args[]) {
		// Create a trust manager that does not validate certificate chains
				TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
						public java.security.cert.X509Certificate[] getAcceptedIssuers() {
							return null;
						}
						public void checkClientTrusted(X509Certificate[] certs, String authType) {
						}
						public void checkServerTrusted(X509Certificate[] certs, String authType) {
						}
					}
				};

				// Install the all-trusting trust manager
				SSLContext sc = null;
				try {
					sc = SSLContext.getInstance("SSL");
				} catch (NoSuchAlgorithmException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				try {
					sc.init(null, trustAllCerts, new java.security.SecureRandom());
				} catch (KeyManagementException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

				// Create all-trusting host name verifier
				HostnameVerifier allHostsValid = new HostnameVerifier() {
					public boolean verify(String hostname, SSLSession session) {
						return true;
					}
				};

				// Install the all-trusting host verifier
				HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
				
		PersonalCloud.DEFAULT_REGISTRY_URI = "https://xdidiscoveryserviceote.xdi.net";
		System.setProperty("https.protocols", "TLSv1");
		//PersonalCloud animeshCloud = PersonalCloud.open(XDI3Segment.create("=animesh"), XDI3Segment.create("$anon") , XDI3Segment.create("$public$do"), "");
		PersonalCloud debishCloud = PersonalCloud.open(XDI3Segment.create("=rctest1"), "aa22@bbb", XDI3Segment.create("$do"), "", "");
		debishCloud.setLinkContractAddress(XDI3Segment.create( debishCloud.getCloudNumber().toString()+ "$to" + debishCloud.getCloudNumber().toString() + "$from$do"));
		System.out.println(debishCloud.getWholeGraph());
		if(debishCloud != null){
			//debishCloud.deleteLinkContract("[=]!:uuid:0b91600d-42f8-4483-8f09-6e59e15ad2e0$to[=]!:uuid:28d89440-4878-407a-8811-be8314a06d9f$from$do","[=]!:uuid:0b91600d-42f8-4483-8f09-6e59e15ad2e0");
			
			Hashtable<String,Object> nvPairs = new Hashtable<String,Object>();
			nvPairs.put(debishCloud.getCloudNumber() + "<#phone>&", "+1.1234567890");
			nvPairs.put(debishCloud.getCloudNumber() + "<#name>&", "John Doe");
			nvPairs.put(debishCloud.getCloudNumber() + "<#email>&", "john.doe@connect.me");
			nvPairs.put(debishCloud.getCloudNumber() + "<#age>&", new Integer(19));
			nvPairs.put(debishCloud.getCloudNumber() + "<#smoker>&", new Boolean(false));
			nvPairs.put(debishCloud.getCloudNumber() + "<#height>&", new Double(5.11));
			debishCloud.saveNameValuePairs(nvPairs);
			System.out.println(debishCloud.getStringLiteral(debishCloud.getCloudNumber() + "<#phone>&"));
			System.out.println(debishCloud.getStringLiteral(debishCloud.getCloudNumber() + "<#age>&"));
			System.out.println(debishCloud.getStringLiteral(debishCloud.getCloudNumber() + "<#smoker>&"));
			
			//debishCloud.getWholeGraph();
			
			//debishCloud.getWholeGraph();
		}
		 //Test.testAddNamedGroup();
		//Test.testAddNamedContext();
		//Test.testAddEntityToNamedGroup();
		//Test.testAccessGranting();
		//Test.testSharedDataAccess();
//		Test.testAccessRemoval();
		//Test.testSharedDataAccess();
		//Test.getAllCollections();
		//Test.testOnOtherPersonalCloudWithDiscovery("=dev.ako");
	//Test.testMyOwnPersonalCloud("=dev.ako", "ga3169723");
		//Test.testSaveProfile("=dev.ako", "ga3169723", "ako@kynetx.com", "1234567890");
		//Test.testPDSXOps();
//		PersonalCloud pc_peer3 = PersonalCloud.open(
//				 XDI3Segment.create("=dev.animesh3"),XDI3Segment.create("[=]!:uuid:91f28153-f600-ae24-91f2-8153f600ae24"),
//				 XDI3Segment.create("$public$do"), "");
//		PersonalCloud pc_peer2 = PersonalCloud.open(
//				 XDI3Segment.create("[=]!:uuid:17864069-1ad0-8bfa-1786-40691ad08bfa"),XDI3Segment.create("[=]!:uuid:91f28153-f600-ae24-91f2-8153f600ae24"),
//				 XDI3Segment.create("$public$do"), "");
//		PersonalCloud pc_peer = PersonalCloud.open(
//				 XDI3Segment.create("[=]!:uuid:91f28153-f600-ae24-91f2-8153f600ae24"),XDI3Segment.create("[=]!:uuid:17864069-1ad0-8bfa-1786-40691ad08bfa"),
//				 XDI3Segment.create("$public$do"), "");
		
		
//		PersonalCloud pc_markus = PersonalCloud.open(
//				 XDI3Segment.create("=markus"), "markus",
//				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "");
//		PersonalCloud pc_animesh = PersonalCloud.open(
//				 XDI3Segment.create("=dev.animesh3"),pc_markus.getCloudNumber(),
//				 XDI3Segment.create("$public$do"), "");
//		PersonalCloud pc_animesh2 = PersonalCloud.open(
//				 XDI3Segment.create("=dev.animesh3"), "animesh123",
//				 PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "");
//		ProfileInfo profileInfo = new ProfileInfo();
//		profileInfo.setEmail("animesh.chowdhury@gmail.com");
//		profileInfo.setPhone("703-724-7686");
//
//		pc1.saveProfileInfo(profileInfo);
		//pc_animesh.getWholeGraph();
		//Test.testDeleteNode();
//		Test.testDefaultLCs();
		//Test.testRelationships();
//		String cn = pc_animesh.getCloudNumber().toString();
//		
//		String reqURI = pc_markus.requestForAccess(XDI3Segment.create(cn+"+home<+phone>&"), XDI3Segment.create("$get"), XDI3Segment.create("+friend"), XDI3Segment.create("+friend"), pc_animesh);
//		
//		
//		pc_animesh2.approveAccess(XDI3Segment.create(reqURI),null);
		//PersonalCloud pc = PersonalCloud.open(XDI3Segment.create("=demo2"), "demo2", PersonalCloud.XRI_S_DEFAULT_LINKCONTRACT, "","");
		
		
//		PersonalCloud pc = PersonalCloud.open(XDI3Segment.create("=will.test"),"willtest",XDI3Segment.create("$do"),"");
//		Hashtable<String,String> youHaveGivenToSomeone = new Hashtable<String,String>();
//		Hashtable<String,String> someoneGaveItToYou = new Hashtable<String,String>();
//		pc.getListofLCs(youHaveGivenToSomeone, someoneGaveItToYou);
		
		
//		//point to the XDI discovery service
//		PersonalCloud.DEFAULT_REGISTRY_URI = "http://mycloud-ote.neustar.biz:12220/";
//
//		//open the personal cloud for test CSP
//		PersonalCloud CSPPersonalCloud = PersonalCloud.open(XDI3Segment.create("@testcsp"),"whitelabel123",XDI3Segment.create("$do"),"");
//
//		 String registrationServiceURI = "https://registration-dev.respectnetwork.net/registration";
//			 
//		PersonalCloud RNPersonalCloud = null; 
//		
//		if (CSPPersonalCloud != null){
//
//		//open personal cloud for Respect Network – target for Registration messages
//
//		RNPersonalCloud = PersonalCloud.open(XDI3Segment.create("@respect"), CSPPersonalCloud.getCloudNumber(),XDI3Segment.create("$public$do"),"");
//		if(RNPersonalCloud != null) {
//			RNPersonalCloud.setLinkContractAddress(XDI3Segment.create(RNPersonalCloud.getCloudNumber().toString() + "$to" + "+registrar$from$do"));
//			//build check cloudname message
//			ArrayList <XDI3Segment> checkNameStatements = new ArrayList <XDI3Segment>();
//			//[@]!:uuid:9999[$msg]!:uuid:1234$do/$get/(=alice)
//			checkNameStatements.add(XDI3Segment.create("(=alice)"));
//			MessageResult checkNameResponse = CSPPersonalCloud.sendQueriesToPeerCloud(RNPersonalCloud,checkNameStatements, null, registrationServiceURI);
//			System.out.println(checkNameResponse);
//		}
//		}

		
//		ProfileInfo profile1 = new ProfileInfo() ; //pc.getProfileInfo("+home");
//		profile1.setCloudName("=animesh.test");
//		profile1.setEmail("animesh.test@someplace.somewhere");
//		profile1.setProfileName("Home Contact");
//		profile1.setName("Animesh Test");
//		profile1.setPhone("bbb-bbb-bbbb");
//		profile1.setRelativeXDIAddress("+newProfile1");
//		String connect = pc.createRespectConnectRequest("+home");
//		profile1.setRespectConnectXDIMessage(connect);
//		pc.createNewProfile(profile1);
//		//pc.deleteProfile("+work");
//pc.getWholeGraph();
		//System.out.println(pc.createRespectConnectRequest("+home").toString());
//		pc.getProfileInfo("+home");
//		profile1.setName("John Doe");
//		profile1.setPhone("666-666-6666");
//		String connect = pc.createRespectConnectRequest("+home");
//		profile1.setRespectConnectXDIMessage(connect);
//		pc.updateProfileInfo(profile1);
//		ProfileInfo prof1 = pc.getProfileInfo("+willtestprofile1");
//		if(prof1 != null){
//		System.out.println(prof1.toString());
//		} else {
//			System.out.println("Profile NOT FOUND!");
//		}
		//pc.deleteProfile("[+profile]!:uuid:79606848-7c7e-4bcd-84e6-5179fbd6d0a1");
		//PDSEmail mail = pc.getEmail("!:uuid:559c0c5c-e1cb-4d7f-b504-b72490f840c9");
		//pc.deleteEmail("!:uuid:559c0c5c-e1cb-4d7f-b504-b72490f840c9");
		//PDSEmail mail2 = pc.getEmail("!:uuid:559c0c5c-e1cb-4d7f-b504-b72490f840c9");
//		Vector<PDSEmail> mails = pc.getEmailBySender("animesh.chowdhury@gmail.com");
//		PDSEmail email = new PDSEmail();
//		email.setFrom("animesh.chowdhury@gmail.com");
//		email.setArrivalTime(new Date());
//		email.setContent("This is another test email");
//		email.setSubject("Test Mail2");
//		
//		//pc.saveEmail(email);
//		pc.getWholeGraph();
//		
//		pc.addEmailLabel(email.getId(), "important");
//		pc.getWholeGraph();
//		pc.removeEmailLabel(email.getId(), "important");
//		pc.getWholeGraph();
//		pc.deleteEmail(email.getId());
//		
//		//pc.getDataBucket("work");
//		String str = "";
//		if(pc == null){
//			System.exit(-1);
//		}
//		
//		FileInputStream fin = null;
//		try {
//			fin = new FileInputStream(args[1]);		
//		} catch (FileNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		DataInputStream din  = new DataInputStream(fin);
//	     BufferedReader d
//         = new BufferedReader(new InputStreamReader(din));
//
//		try {
//			String line ;
//			while((line = d.readLine()) != null){
//				str += line;
//			}
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		Graph g = pc.signGraph(str, "[=]!:uuid:0707f2ff-4266-9f14-0707-f2ff42669f14");
//		Graph g = pc.getWholeGraph();
//		g = pc.signGraph(Signature.getNormalizedSerialization(g.getRootContextNode()), "");
//		StringWriter writer = new StringWriter();
//		XDIWriter xdiResultWriter = XDIWriterRegistry.forFormat("XDI DISPLAY", null);
//
//        try {
//			xdiResultWriter.write(g, writer);
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//
//        String output = writer.getBuffer().toString();
//        System.out.println("\n Signed Graph:\n" + output + "\n");
//        boolean valid= PersonalCloud.verifySignature(output, "", pc.getCloudNumber().toString());
//		
//		String respectConnectRequest = new String();
//		
//		FileInputStream fin = null;
//		try {
//			fin = new FileInputStream(args[0]);		} catch (FileNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		DataInputStream din  = new DataInputStream(fin);
//	     BufferedReader d
//         = new BufferedReader(new InputStreamReader(din));
//
//		try {
//			String line ;
//			while((line = d.readLine()) != null){
//				respectConnectRequest += line;
//			}
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		
//		PersonalCloud.verifyMessageSignature(respectConnectRequest);
//		String [] checkedValues = new String[1];
//		checkedValues[0] = new String("[=]!:uuid:678ac1a4-4b52-7610-678a-c1a44b527610<+email>&|demo2@newdemoland.com");
		//pc.processApprovalForm("{$from}[@]!:uuid:e0178407-b7b6-43f9-e017-8407b7b643f9+registration$do", "[@]!:uuid:e0178407-b7b6-43f9-e017-8407b7b643f9", "[=]!:uuid:678ac1a4-4b52-7610-678a-c1a44b527610", "demo2", checkedValues,"http://success","http://failure","=demo2","relayMe") ;
		//pc.showAuthenticationForm(respectConnectRequest, "=demo2","[=]!:uuid:678ac1a4-4b52-7610-678a-c1a44b527610");
		//pc.showApprovalForm(respectConnectRequest, "[=]!:uuid:678ac1a4-4b52-7610-678a-c1a44b527610", "demo2","http://success","http://failure","=demo2","relayMe");
		//pc.linkContractExists(respectConnectRequest);
	}
}

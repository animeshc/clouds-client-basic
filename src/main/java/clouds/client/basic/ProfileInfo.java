package clouds.client.basic;

import xdi2.core.xri3.XDI3Segment;

public class ProfileInfo implements PersonalCloudEntity {

	private String cloudName;
	private String cloudNumber;
	private String profileName;
	private String relativeXDIAddress;
	private String name;
	private String organization;
	private String title;
	private String webAddress;
	private byte[] photo;
	private String oneLiner;
	private String email;
	private String phone;
	private String profileContextId;
	private boolean isDefaultProfile = false;
	private String respectConnectXDIMessage;
	
	public XDI3Segment getAddress(PersonalCloud pc) {
		
		return pc.getCloudNumber(); 
	}

	//public ValueObject zip;
	
	public String getEmail() {

		return this.email;
	}

	public void setEmail(String email) {

		this.email = email;
	}

	public String getPhone() {

		return this.phone;
	}

	public void setPhone(String phone) {

		this.phone = phone;
	}

	@Override
	public String toString() {

		StringBuffer str = new StringBuffer();
		str.append("Email:" + email).append(",XDI Context:" + relativeXDIAddress);
		return str.toString();
	}

	public String getCloudName() {
		return cloudName;
	}

	public void setCloudName(String cloudName) {
		this.cloudName = cloudName;
	}

	public String getCloudNumber() {
		return cloudNumber;
	}

	public void setCloudNumber(String cloudNumber) {
		this.cloudNumber = cloudNumber;
	}

	public String getProfileName() {
		return profileName;
	}

	public void setProfileName(String profileName) {
		this.profileName = profileName;
	}

	public String getRelativeXDIAddress() {
		if(relativeXDIAddress == null || relativeXDIAddress.isEmpty()){
			return "+profile+default";
		}
		if(relativeXDIAddress.startsWith("+profile")) {
			return relativeXDIAddress;
		} else {
			return "+profile" +  relativeXDIAddress;
		}
	}

	public void setRelativeXDIAddress(String p_relativeXDIAddress) {
		if(p_relativeXDIAddress == null || p_relativeXDIAddress.isEmpty()){
			this.relativeXDIAddress = "+profile+default";
		}
		if(p_relativeXDIAddress.startsWith("+profile")) {
			this.relativeXDIAddress = p_relativeXDIAddress;
		} else {
			this.relativeXDIAddress = "+profile" +  p_relativeXDIAddress;	
		}
	}

	public String getOrganization() {
		return organization;
	}

	public void setOrganization(String organization) {
		this.organization = organization;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getWebAddress() {
		return webAddress;
	}

	public void setWebAddress(String webAddress) {
		this.webAddress = webAddress;
	}

	public byte[] getPhoto() {
		return photo;
	}

	public void setPhoto(byte[] photo) {
		this.photo = photo;
	}

	public String getOneLiner() {
		return oneLiner;
	}

	public void setOneLiner(String oneLiner) {
		this.oneLiner = oneLiner;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getProfileContextId() {
		return profileContextId;
	}

	public void setProfileContextId(String profileContextId) {
		this.profileContextId = profileContextId;
	}

	public boolean isDefault() {
		return isDefaultProfile;
	}

	public void setDefault(boolean isDefault) {
		this.isDefaultProfile = isDefault;
	}

	public String getRespectConnectXDIMessage() {
		return respectConnectXDIMessage;
	}

	public void setRespectConnectXDIMessage(String respectConnectXDIMessage) {
		this.respectConnectXDIMessage = respectConnectXDIMessage;
	}
	
	
}

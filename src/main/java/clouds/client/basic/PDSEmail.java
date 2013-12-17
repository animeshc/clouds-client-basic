package clouds.client.basic;

import java.util.Date;
import java.util.Vector;

public class PDSEmail {

	private String from;
	
	private String subject;
	private Date arrivalTime;
	private String content;
	private Vector<Microtag> tagList = new Vector<Microtag>();
	private int priority = 0;
	private int flag = 0;
	private String operation = "ADD";
	
	public String getOperation() {
		return operation;
	}
	public void setOperation(String operation) {
		this.operation = operation;
	}
	public int getFlag() {
		return flag;
	}
	public void setFlag(int flag) {
		this.flag = flag;
	}
	public int getPriority() {
		return priority;
	}
	public void setPriority(int priority) {
		this.priority = priority;
	}
	public String getFrom() {
		return from;
	}
	public void setFrom(String from) {
		this.from = from;
	}
	
	public String getSubject() {
		return subject;
	}
	public void setSubject(String subject) {
		this.subject = subject;
	}
	public Vector<Microtag> getTagList() {
		return tagList;
	}
	public void setTagList(Vector<Microtag> tagList) {
		this.tagList = tagList;
	}
	public Date getArrivalTime() {
		return arrivalTime;
	}
	public void setArrivalTime(Date arrivalTime) {
		this.arrivalTime = arrivalTime;
	}
	public String getContent() {
		return content;
	}
	public void setContent(String content) {
		this.content = content;
	}
	public void addTag(Microtag tag){
		tagList.add(tag);
	}
	public void removeTag(Microtag tag){
		int i = 0;
		for(Microtag theTag : tagList){
			
			if(theTag.getName().equals(tag.getName())){
				theTag.setOperation("REMOVE");
				break;
			}
			i++;
		}
	}
	public void updateTag(Microtag tag){
		int i = 0;
		for(Microtag theTag : tagList){
			
			if(theTag.getName().equals(tag.getName())){
				theTag.setOperation("UPDATE");
				break;
			}
			i++;
		}
		
	}
	
}

package clouds.client.basic;

import java.util.Date;
import java.util.Vector;

public class PDSEmail {

	private String from;
	
	private String subject;
	private Date arrivalTime;
	private String content;
	
	private int priority = 0;
	private int flag = 0;
	private String operation = "ADD";
	
	private String id;
	
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
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
	
	@Override
	public String toString(){
		StringBuffer str = new StringBuffer();
		str.append("\n");
		str.append("id :" + this.id + "\n");
		str.append("from :" + this.from + "\n");
		str.append("subject :" + this.subject + "\n");
		str.append("arrival time :" + this.arrivalTime + "\n");
		return str.toString();
	}
	
	
	
}

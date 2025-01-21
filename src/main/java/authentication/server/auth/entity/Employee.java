package authentication.server.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "employees")
public class Employee {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long employeeId;

	@Column(length = 20,name = "employee_name")
	private String employeeName;
	@Column(name = "employee_surname", nullable = false)
	private String employeeSurName;
	@Column(length = 50, name = "employee_email")
	private String employeeEmail;
	@Enumerated(EnumType.STRING)
	@Column(name = "employee_role")
	private Role role;
	
	public Long getEmployeeId() {
		return employeeId;
	}
	public void setEmployeeId(Long employeeId) {
		this.employeeId = employeeId;
	}
	public String getEmployeeName() {
		return employeeName;
	}
	public void setEmployeeName(String employeeName) {
		this.employeeName = employeeName;
	}
	public String getEmployeeSurName() {
		return employeeSurName;
	}
	public void setEmployeeSurName(String employeeSurName) {
		this.employeeSurName = employeeSurName;
	}

	public String getEmployeeEmail() {
		return employeeEmail;
	}
	public void setEmployeeEmail(String employeeEmail) {
		this.employeeEmail = employeeEmail;
	}
	public Role getRole() {
		return role;
	}
	public void setRole(Role role) {
		this.role = role;
	}
	public Employee(Long employeeId, String employeeName, String employeeSurName, String employeeEmail, Role role) {
		super();
		this.employeeId = employeeId;
		this.employeeName = employeeName;
		this.employeeSurName = employeeSurName;
		this.employeeEmail = employeeEmail;
		this.role = role;
	}
	public Employee() {
		super();
	}

	

}

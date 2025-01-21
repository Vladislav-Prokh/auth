package authentication.server.auth.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.crossstore.ChangeSetPersister.NotFoundException;
import org.springframework.stereotype.Service;
import authentication.server.auth.entity.Employee;
import authentication.server.auth.entity.Role;
import authentication.server.auth.exceptions.ResourceNotFoundException;
import authentication.server.auth.repositories.EmployeeRepository;


@Service
public class EmployeeService {
	@Autowired
	private EmployeeRepository employeeRepository;

	public Employee saveEmployee(Employee employee) {
		return this.employeeRepository.save(employee);
	}

	public Employee findEmployeeById(Long employeeId) throws NotFoundException {
		return this.employeeRepository.findById(employeeId).orElseThrow(() -> new ResourceNotFoundException("employee not found"));
	}

	public Employee findByEmployeeEmail(String email) {
		return this.employeeRepository.findByEmployeeEmail(email);
	}
	
	public void deleteEmployeById(Long employee_id) {
		this.employeeRepository.deleteById(employee_id);
	}

	public void assignRole(Long employeeId, String role) {

	    Employee employee = employeeRepository.findById(employeeId).orElseThrow(() -> new ResourceNotFoundException("employee not found"));
        Role newRole = Role.valueOf(role.toUpperCase());
        
        employee.setRole(newRole);
        this.employeeRepository.save(employee);

	}
}
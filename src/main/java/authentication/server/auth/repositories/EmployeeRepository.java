package authentication.server.auth.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import authentication.server.auth.entity.Employee;

public interface EmployeeRepository extends JpaRepository<Employee,Long>{
	public Employee findByEmployeeEmail(String employeeName);
}

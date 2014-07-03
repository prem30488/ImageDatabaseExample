package com.dao;

import java.util.List;

import com.models.User;

public interface UserDAO {

	public void saveUser(User user);
	public List<User> listUser();
}

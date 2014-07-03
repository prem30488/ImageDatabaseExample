package com.action;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.Blob;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.FileUtils;
import org.apache.struts2.interceptor.ServletRequestAware;
import org.hibernate.Hibernate;

import com.opensymphony.xwork2.ActionSupport;
import com.opensymphony.xwork2.ModelDriven;
import com.dao.UserDAO;
import com.dao.UserDAOImpl;
import com.models.User;

public class UserAction extends ActionSupport implements ModelDriven<User>,ServletRequestAware  {

	private static final long serialVersionUID = 1L;
	private User user = new User();
	private List<User> userList = new ArrayList<User>();
	private UserDAO userDAO = new UserDAOImpl();
	private File file;
	public HttpServletRequest request;
	
	public User getModel() {
		return user;
	}
	

	public boolean validate2()
	{
		System.out.println("validate method");
		// Checking the mandatory fields
        if("".equals(user.getName().trim()))
        {
            addFieldError("name", getText("User Name required"));
            return false;
        }
        
        return true;
	}
	
	public String execute()
	{
		if(validate2())
		{
		System.out.println("execute method");
		try {
		     FileInputStream fileInputStream = new FileInputStream(file);
		     Blob blob = Hibernate.createBlob(fileInputStream);
		     user.setPhoto(blob);
	        } catch (Exception e) {
		     e.printStackTrace();
	        }
		userDAO.saveUser(user);
		return SUCCESS;
		}
		else
		{
			return INPUT;
		}
	}
	
	@SuppressWarnings("deprecation")
	public String list()
	{
		try {
			System.out.println("Deleteing "+request.getRealPath("/")+"images\\"+" folder files");
			FileUtils.cleanDirectory(new File(request.getRealPath("/")+"images\\"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Error in deleting files in images folder");
			System.out.println(e.getMessage());
		} 
		userList = userDAO.listUser();
		if(userList.size()>0)
		{
			for(int i=0;i<userList.size();i++)
			{
				byte[] bAvatar;
				try {
					if(userList.get(i).getPhoto()!=null)
					{
						bAvatar = userList.get(i).getPhoto().getBytes(1, (int) userList.get(i).getPhoto().length());
						System.out.println(request.getRealPath("/")+"images\\"+userList.get(i).getId().toString()+".jpg");
			            FileOutputStream fos = new FileOutputStream(request.getRealPath("/")+"images\\"+userList.get(i).getId().toString()+".jpg"); 
			            fos.write(bAvatar);
			            fos.close();
			            bAvatar=null;
					}
		        }catch(Exception e){
		            e.printStackTrace();
		        }
			}
		}
		
		return SUCCESS;
	}
		
	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}

	public List<User> getUserList() {
		return userList;
	}

	public void setUserList(List<User> userList) {
		this.userList = userList;
	}

	public void setFile(File file) {
		this.file = file;
	}

	public File getFile() {
		return file;
	}

	@Override
	public void setServletRequest(HttpServletRequest request) {
		// TODO Auto-generated method stub
		this.request = request; 
	}

}

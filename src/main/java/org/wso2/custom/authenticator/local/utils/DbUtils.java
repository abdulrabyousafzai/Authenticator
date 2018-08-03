package org.wso2.custom.authenticator.local.utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;


public class DbUtils {

	private static volatile DataSource mConnectDatasource = null;
	private static final Log log = LogFactory.getLog(DbUtils.class);

	public static boolean insertSMSPIN(String msisdn) throws AuthenticationFailedException {
		Statement stmt = null;
		boolean status =false;
		Hashtable environment = new Hashtable();
		environment.put("java.naming.factory.initial", "org.wso2.carbon.tomcat.jndi.CarbonJavaURLContextFactory");
		Context initContext;
		Connection conn = null;
		PreparedStatement ps = null;
		ResultSet results = null;
		try {
			initContext = new InitialContext(environment);
			DataSource ds = (DataSource)initContext.lookup("jdbc/ussd");
			if (ds != null) {
				conn = ds.getConnection();
				String sql = "SELECT * FROM `Test` WHERE `Msisdn` =" + msisdn;
				stmt = conn.createStatement();
				ResultSet rs = stmt.executeQuery(sql);
				if (rs.next()){
					String rsmsisdn = rs.getString("Msisdn");
					if(rsmsisdn.equals(msisdn)){
						status =true;
					}
				}
				rs.close();
			}
		}
		catch (Exception e1) {
			String ec=e1.toString();
		}finally {
			if (stmt != null) {
				try {
					stmt.close();
				} catch (SQLException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}}
			try {
				if(conn!=null){
					conn.close();
				}
			}catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		return status;
	}




}

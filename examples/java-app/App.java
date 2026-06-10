package com.app;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class App {
    public void queryUser(String id) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "");
        Statement stmt = conn.createStatement();
        // SQL Injection (vulnerable to security/sql-injection)
        stmt.execute("SELECT * FROM users WHERE id = '" + id + "'");
    }

    public void parseXml(String xmlData) throws Exception {
        // XML External Entity (XXE) (vulnerable to security/xxe)
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new java.io.ByteArrayInputStream(xmlData.getBytes()));
    }
}

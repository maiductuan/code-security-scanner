package com.app;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class AppSafe {
    public void queryUser(String id) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "root", "");
        // Safe: using PreparedStatement
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, id);
        stmt.execute();
    }

    public void parseXml(String xmlData) throws Exception {
        // Safe: disabling external DTDs and entities to prevent XXE
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new java.io.ByteArrayInputStream(xmlData.getBytes()));
    }
}

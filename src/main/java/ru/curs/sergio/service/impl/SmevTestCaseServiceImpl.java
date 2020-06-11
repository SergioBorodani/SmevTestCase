package ru.curs.sergio.service.impl;

import com.digt.trusted.jce.provider.DIGTProvider;
import com.digt.trusted.xmlsig.Consts;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
import ru.curs.celesta.CallContext;
import ru.curs.celesta.transaction.CelestaTransaction;
import ru.curs.sergio.service.SmevTestCaseService;
import ru.curs.sergio.spring.boot.properties.SmevTestCaseProperties;
import ru.curs.sergio.utils.SmevTransformSpi;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.lang.reflect.Field;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;
import ru.curs.smev.*;

@Service
public class SmevTestCaseServiceImpl implements SmevTestCaseService {

    private static final Logger LOGGER = LoggerFactory
            .getLogger(SmevTestCaseServiceImpl.class);

    private final SmevTestCaseProperties properties;

    public SmevTestCaseServiceImpl(SmevTestCaseProperties properties) {
        this.properties = properties;

        File xmlServiceDir = new File(this.properties.getXmlServiceDir());
        if (!xmlServiceDir.exists()) {
            xmlServiceDir.mkdirs();
        }
    }

    private class SmevResult {
        private boolean success;

        private String xml;

        public boolean isSuccess() {
            return success;
        }

        public void setSuccess(boolean success) {
            this.success = success;
        }

        public String getXml() {
            return xml;
        }

        public void setXml(String xml) {
            this.xml = xml;
        }
    }

    private static final class SmevStatus {

        public static final Integer SUCCESS = 0;

        public static final Integer ERROR = 1;

        private SmevStatus() {
            throw new AssertionError();
        }
    }

    @Override
    public void initialize() {
        try {
            Security.addProvider(new DIGTProvider());

            System.setProperty(Consts.PROPERTY_NAME, Consts.CONFIG);
            org.apache.xml.security.Init.init();

            Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class.getName());

            Boolean currMode = true;
            AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {

                public Boolean run() throws Exception {
                    Field f = XMLUtils.class.getDeclaredField("ignoreLineBreaks");
                    f.setAccessible(true);
                    f.set(null, currMode);
                    return false;
                }
            });
        } catch (Exception e) {

            LOGGER.error("", e);

            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    @CelestaTransaction
    public void getFromSmev(CallContext callContext) {
        LOGGER.info("Начало опроса очереди СМЭВ");

        boolean queueIsNotEmpty = true;
        while (queueIsNotEmpty) {
            String getResponseRequest = getResponseRequest();
            SmevResult sr = connectToSg2(getResponseRequest);
            LOGGER.info(sr.getXml());

            if (isSmevQueueEmpty(sr.getXml())) {
                queueIsNotEmpty = false;
                continue;
            }

//            String mesId = parseMessageId(sr.getXml());
//
//            String ackRequest = ackRequest(mesId);
//
//            String ackUuid = UUID.randomUUID().toString();
//
//            String ackHash = pathGenerator(ackUuid, true);
//
//            SmevServiceMessageCursor smevServiceMessageCursor = new SmevServiceMessageCursor(callContext);
//
//            try {
//                String ackRequestFileName = ackHash + "/" + "Ack_" + ackUuid + "_Request.xml";
//                PrintWriter printWriter = new PrintWriter(properties.getXmlServiceDir() + "/" + ackRequestFileName);
//                printWriter.print(ackRequest);
//                printWriter.flush();
//                printWriter.close();
//
//                smevServiceMessageCursor.setXml_file_request(ackRequestFileName);
//
//            } catch (Exception e) {
//                throw new RuntimeException(e.getMessage(), e);
//            }
//
//            smevServiceMessageCursor.setOriginal_message_id(mesId);
//
//            LOGGER.info(ackRequest);
//
//            Date ackInitialDate = new Date();
//
//            smevServiceMessageCursor.setInitial_message_time_stamp(ackInitialDate);
//
//            sr = connect(ackRequest);
//
//            Date ackLastUpdateDate = new Date();
//
//            smevServiceMessageCursor.setLast_update_time_stamp(ackLastUpdateDate);
//
//            try {
//                String ackResponseFileName = ackHash + "/" + "Ack_" + ackUuid + "_Response.xml";
//                PrintWriter printWriter = new PrintWriter(properties.getXmlServiceDir() + "/" + ackResponseFileName);
//                printWriter.print(sr.getXml());
//                printWriter.flush();
//                printWriter.close();
//
//                smevServiceMessageCursor.setXml_file_response(ackResponseFileName);
//
//            } catch (Exception e) {
//                throw new RuntimeException(e.getMessage(), e);
//            }
//
//            smevServiceMessageCursor.setSmev_status(SmevStatus.SUCCESS);
//
//            smevServiceMessageCursor.tryInsert();
//
//            LOGGER.info(sr.getXml());

            //@@@
            queueIsNotEmpty = false;
        }

        LOGGER.info("Конец опроса очереди СМЭВ");
    }

    String pathGenerator(String fileName, boolean ack) {
        String[] parts = null;

        if(fileName.contains("Modified")) {
            parts = fileName.split("Modified");
            fileName = parts[0] + parts[1];
        }

        int hash = fileName.hashCode();
        int mask = 255;
        int firstDir = hash & mask;

        String path = String.format("%02x", firstDir);

        File f = new File(properties.getXmlServiceDir() + "/" + path);

        if (ack) {
            f = new File(properties.getXmlServiceDir() + "/" + path);
        }

        f.mkdirs();

        if(parts != null) {
            fileName = parts[0] + "Modified" + parts[1];
        }

        return ack ? path : path + "/" + fileName;
    }

    String getContentByTag(String xml, String tag, boolean include) {

        class MyHandler extends DefaultHandler {

            private boolean b = false;
            private String content = "";
            private StringBuilder builder = new StringBuilder();

            public String getTagContent() {
                return builder.toString();
            }

            @Override
            public void characters(char[] ch, int start, int length) throws SAXException {
                if (b) {
                    content = new String(ch, start, length);

                    if (!content.isEmpty()) {
                        builder.append(content);
                    }
                }
            }

            @Override
            public void startElement(String uri, String lName, String qName, Attributes attr) throws SAXException {
                String tagName = qName;
                if(qName.contains(":")) {
                    int index = qName.lastIndexOf(":");
                    tagName = qName.substring(index + 1);
                }
                if (tagName.equals(tag)) {
                    b = true;

                    if (include) {
                        appendStartTag(qName, attr);
                    }
                }
                if (b && !tagName.equals(tag)) {
                    appendStartTag(qName, attr);
                }
            }

            @Override
            public void endElement(String uri, String localName, String qName) throws SAXException {
                if (qName.contains(tag)) {
                    b = false;

                    if (include) {
                        appendEndTag(qName);
                    }
                }
                if (b && !qName.contains(tag)) {
                    appendEndTag(qName);
                }
            }

            private void appendStartTag(String qName, Attributes attr) {
                builder.append("<" + qName);
                if (attr.getLength() > 0) {
                    for (int i = 0; i < attr.getLength(); i++) {
                        builder.append(" " + attr.getQName(i) + "=\"" + attr.getValue(i) + "\"");
                    }
                }
                builder.append(">");
            }

            private void appendEndTag(String qName) {
                builder.append("</" + qName + ">");
            }
        }

        MyHandler handler = new MyHandler();

        try {
            InputStream stream = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(stream, handler);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        return handler.getTagContent();
    }


    public String parseMessageId(String xml) {
        try {

            xml = getContentByTag(cutRespResp(xml), "Envelope", true);

            InputSource is = new InputSource(new StringReader(xml));

            final DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setIgnoringElementContentWhitespace(true);
            dbf.setCoalescing(true);
            dbf.setNamespaceAware(true);
            final DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            final Document doc = documentBuilder.parse(is);

            NodeList nodeList = doc.getElementsByTagName("ns2:MessageID");
            if (nodeList.getLength() == 0) {
                throw new RuntimeException("Cannot find element");
            }

            String uid = nodeList.item(0).getFirstChild().getNodeValue();

            return uid;
        } catch (Exception e) {

            LOGGER.error("", e);

            throw new RuntimeException(e.getMessage(), e);
        }
    }

    boolean isSmevQueueEmpty(String xml) {

        if (xml.startsWith("<html>")) {
            return true;
        }

        class MyHandler extends DefaultHandler {

            private boolean tagGetResponseResponseExists = false;
            private boolean b = false;
            private String content = "";

            public boolean isSmevQueueEmpty() {
                return !tagGetResponseResponseExists || (tagGetResponseResponseExists && content.isEmpty());
            }

            @Override
            public void characters(char[] ch, int start, int length) throws SAXException {
                if (b) {
                    content = content + new String(ch, start, length);
                }
            }

            @Override
            public void startElement(String uri, String lName, String qName, Attributes attr) throws SAXException {
                if (qName.contains("GetResponseResponse")) {
                    tagGetResponseResponseExists = true;
                    b = true;
                }
            }

            @Override
            public void endElement(String uri, String localName, String qName) throws SAXException {
                if (qName.contains("GetResponseResponse")) {
                    b = false;
                }
            }
        }

        MyHandler handler = new MyHandler();

        try {
            InputStream stream = new ByteArrayInputStream(cutRespResp(xml).getBytes(StandardCharsets.UTF_8));
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(false);
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(stream, handler);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        return handler.isSmevQueueEmpty();
    }

    String cutRespResp(String xml) {
        if (xml.contains("<soap:Envelope")) {

            int index1 = xml.indexOf("<soap:Envelope");
            int index2 = xml.indexOf("</soap:Envelope>");

            xml = xml.substring(index1, index2 + "</soap:Envelope>".length());
        }

        return xml;
    }

    String getResponseRequest() {
        try {
            KeyStore store = KeyStore.getInstance("CryptoProCSPKeyStore", "DIGT");
            store.load(new ByteArrayInputStream(properties.getStore().getBytes("UTF-8")), null);

            PrivateKey privKey = (PrivateKey) store.getKey(properties.getAlias(), properties.getStorePassword().toCharArray());

            X509Certificate cert = (X509Certificate) store.getCertificate(properties.getAlias());

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setIgnoringElementContentWhitespace(true);
            dbf.setCoalescing(true);
            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();

            String pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";

            DateFormat df = new SimpleDateFormat(pattern);

            String timestamp = df.format(new Date());

            String xmlInput =
                    "<ns2:MessageTypeSelector Id=\"SIGNED_BY_CALLER\" " +
                            "xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\">" +
                            "<ns2:Timestamp>" + timestamp + "</ns2:Timestamp>" +
                            "</ns2:MessageTypeSelector>";

            InputSource is = new InputSource(new StringReader(xmlInput));

            Document doc = documentBuilder.parse(is);

            //!!!
            Element element = doc.getDocumentElement();
            element.setAttributeNS(null, "Id", "SIGNED_BY_CALLER");
            Attr idAttr = element.getAttributeNode("Id");
            element.setIdAttributeNode(idAttr, true);

            XMLSignature sig = new XMLSignature(doc, "", algUri, "http://www.w3.org/2001/10/xml-exc-c14n#");
            sig.setId("sigID");
            Transforms transforms = new Transforms(doc);
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            transforms.addTransform(SmevTransformSpi.ALGORITHM_URN);
            sig.addDocument("#SIGNED_BY_CALLER", transforms, digUri);
            sig.addKeyInfo(cert);
            sig.sign(privKey);

            StringWriter sw = new StringWriter();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            trans.transform(new DOMSource(sig.getElement()), new StreamResult(sw));

            String result = //"<?xml version='1.0' encoding='UTF-8'?>" +
                    "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
                            "<S:Body>" +
                            "<GetResponseRequest " +
                            "xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" " +
                            "xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\" " +
                            "xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">" +
                            xmlInput +
                            "<CallerInformationSystemSignature>" +
                            sw.toString() +
                            "</CallerInformationSystemSignature>" +
                            "</GetResponseRequest>" +
                            "</S:Body>" +
                            "</S:Envelope>";

            return result;

        } catch (Exception e) {

            LOGGER.error("", e);

            throw new RuntimeException(e.getMessage(), e);
        }
    }

    String ackRequest(String mesId) {

        try {
            KeyStore store = KeyStore.getInstance("CryptoProCSPKeyStore", "DIGT");
            store.load(new ByteArrayInputStream(properties.getStore().getBytes("UTF-8")), null);

            PrivateKey privKey = (PrivateKey) store.getKey(properties.getAlias(), properties.getStorePassword().toCharArray());

            X509Certificate cert = (X509Certificate) store.getCertificate(properties.getAlias());

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setIgnoringElementContentWhitespace(true);
            dbf.setCoalescing(true);
            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();

            String xmlInput =
                    "<ns2:AckTargetMessage " +
                            "xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\" " +
                            "xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" " +
                            "Id=\"SIGNED_BY_CALLER\" accepted=\"true\">" + mesId +
                            "</ns2:AckTargetMessage>";

            InputSource is = new InputSource(new StringReader(xmlInput));

            final Document doc = documentBuilder.parse(is);

            //!!!
            Element element = doc.getDocumentElement();
            element.setAttributeNS(null, "Id", "SIGNED_BY_CALLER");
            Attr idAttr = element.getAttributeNode("Id");
            element.setIdAttributeNode(idAttr, true);

            final XMLSignature sig = new XMLSignature(doc, "", algUri, "http://www.w3.org/2001/10/xml-exc-c14n#");
            sig.setId("sigID");
            Transforms transforms = new Transforms(doc);
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            transforms.addTransform(SmevTransformSpi.ALGORITHM_URN);
            sig.addDocument("#SIGNED_BY_CALLER", transforms, digUri);
            sig.addKeyInfo(cert);
            sig.sign(privKey);

            StringWriter sw = new StringWriter();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            trans.transform(new DOMSource(sig.getElement()), new StreamResult(sw));

            String result = //"<?xml version='1.0' encoding='UTF-8'?>" +
                    "<S:Envelope xmlns:S=\"http://schemas.xmlsoap.org/soap/envelope/\">" +
                            "<S:Body>" +
                            "<AckRequest " +
                            "xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" " +
                            "xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\" " +
                            "xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">" +
                            xmlInput +
                            "<CallerInformationSystemSignature>" +
                            sw.toString() +
                            "</CallerInformationSystemSignature>" +
                            "</AckRequest>" +
                            "</S:Body>" +
                            "</S:Envelope>";

            return result;

        } catch (Exception e) {

            LOGGER.error("", e);

            throw new RuntimeException(e.getMessage(), e);
        }
    }

    SmevResult connectToSg2(String xmlInput) {
        try {

            byte[] b = xmlInput.getBytes();

            String wsEndPoint = properties.getSg2Url();
            URL url = new URL(wsEndPoint);
            URLConnection connection = url.openConnection();
            HttpURLConnection httpConn = (HttpURLConnection) connection;
            httpConn.setRequestMethod("POST");
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");

            OutputStream out = httpConn.getOutputStream();

            out.write(b);
            out.flush();

            httpConn.connect();
            Integer respCode = httpConn.getResponseCode();

            LOGGER.info(respCode.toString());

            SmevResult sr = new SmevResult();

            if (httpConn.getErrorStream() == null) {
                LOGGER.info("Error NULL");

                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;
                while ((length = httpConn.getInputStream().read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                sr.setSuccess(true);
                sr.setXml(result.toString("UTF-8"));
            } else {
                LOGGER.info("Error NOT NULL");

                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;
                while ((length = httpConn.getErrorStream().read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                sr.setSuccess(false);
                sr.setXml(result.toString("UTF-8"));
            }

            httpConn.disconnect();

            return sr;

        } catch (Exception e) {

            LOGGER.error("", e);

            throw new RuntimeException(e.getMessage(), e);
        }
    }

    SmevResult connect(String xmlInput) {
        try {

            byte[] b = xmlInput.getBytes();

            String wsEndPoint = properties.getUrl();
            URL url = new URL(wsEndPoint);
            URLConnection connection = url.openConnection();
            HttpURLConnection httpConn = (HttpURLConnection) connection;
            httpConn.setRequestMethod("POST");
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");

            OutputStream out = httpConn.getOutputStream();

            out.write(b);
            out.flush();

            httpConn.connect();
            Integer respCode = httpConn.getResponseCode();

            LOGGER.info(respCode.toString());

            SmevResult sr = new SmevResult();

            if (httpConn.getErrorStream() == null) {
                LOGGER.info("Error NULL");

                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;
                while ((length = httpConn.getInputStream().read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                sr.setSuccess(true);
                sr.setXml(result.toString("UTF-8"));
            } else {
                LOGGER.info("Error NOT NULL");

                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;
                while ((length = httpConn.getErrorStream().read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                sr.setSuccess(false);
                sr.setXml(result.toString("UTF-8"));
            }

            httpConn.disconnect();

            return sr;

        } catch (Exception e) {

            LOGGER.error("", e);

            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    public String getNalogResponse(String timeBasedUuid) {
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<tns:FAKTUPNALResponse IDRequest=\"5247016429_ID\" xmlns:tns=\"urn://x-artefacts-fns-faktupnal/root/085-01/4.0.0\">" +
	            "<tns:DataAmountPaidTaxes DateInfoAvailable=\"2015-09-01\" AmountPaidTaxes=\"462132\" LegalPersonINN=\"5247016429\"/>" +
                "</tns:FAKTUPNALResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";

        /*String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<tns:FAKTUPNALResponse xmlns:tns=\"urn://x-artefacts-fns-faktupnal/root/085-01/4.0.0\" IDRequest=\"7729588182_ID\">\n" +
                "\t<tns:TreatmentCode>01</tns:TreatmentCode>\n" +
                "</tns:FAKTUPNALResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";*/

        return testResponseXml;
    }

    @Override
    public String getSnilsResponse(String timeBasedUuid) {

        //ПаспортРФ
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>МАРТЫНОВА</FamilyName>" +
                "<FirstName>СВЕТЛАНА</FirstName>" +
                "<Patronymic>АЛЕКСАНДРОВНА</Patronymic>" +
                "<ns2:Snils>03983240978</ns2:Snils>" +
                "<ns2:BirthDate>1949-02-11</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>с. Ломовое</ns3:Settlement>" +
                "<ns3:District>Чаплыгинский</ns3:District>" +
                "<ns3:Region>Липецкая область</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<PassportRF>" +
                "<Series>4202</Series>" +
                "<Number>766675</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данныхххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххххх</Issuer>" +
                "</PassportRF>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";

        /* //Свидетельство о рождении
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<BirthCertificate>" +
                "<Series>I-РД</Series>" +
                "<Number>756107</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</BirthCertificate>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";*/

        /*//Загранпаспорт
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<InternationalPassportRF>" +
                "<Series>12</Series>" +
                "<Number>7561078</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</InternationalPassportRF>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";*/
/*
        //Военный билет
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<MilitaryPassport>" +
                "<Series>АЯ</Series>" +
                "<Number>1234567</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</MilitaryPassport>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";*/
/*
        //Паспорт иностранного гражданина
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<ForeignPassport>" +
                "<Series>12</Series>" +
                "<Number>1234567</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</ForeignPassport>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>MIIHSjCCBvegAwIBAgIQcgsBVlAAT4DpEfJ6Z5xyNzAKBggqhQMHAQEDAjCCAT8xGDAWBgUqhQNkARINMTAyNzcwMDE5ODc2NzEaMBgGCCqFAwOBAwEBEgwwMDc3MDcwNDkzODgxCzAJBgNVBAYTAlJVMSkwJwYDVQQIDCA3OCDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszEmMCQGA1UEBwwd0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxWDBWBgNVBAkMTzE5MTAwMiwg0LMuINCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzLCDRg9C7LiDQlNC+0YHRgtC+0LXQstGB0LrQvtCz0L4g0LQuMTUxJjAkBgNVBAoMHdCf0JDQniAi0KDQvtGB0YLQtdC70LXQutC+0LwiMSUwIwYDVQQDDBzQotC10YHRgtC+0LLRi9C5INCj0KYg0KDQotCaMB4XDTE5MDUyMDExMTcxNVoXDTIwMDUyMDExMjcxNVowgeYxGjAYBggqhQMDgQMBARIMMDA3NzA3MDQ5Mzg4MRgwFgYFKoUDZAESDTEwMjc3MDAxOTg3NjcxKDAmBgNVBAoMH9Cf0JDQniDCq9Cg0L7RgdGC0LXQu9C10LrQvtC8wrsxJjAkBgNVBAcMHdCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMS0wKwYDVQQIDCQ3OCDQsy4g0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxCzAJBgNVBAYTAlJVMSAwHgYDVQQDDBfQotCm0J7QlF/QodCc0K3QkjNf0K3QnDBmMB8GCCqFAwcBAQEBMBMGByqFAwICJAAGCCqFAwcBAQICA0MABEAFxzu1R0MSKe8/eSNtseE8LZMNIqbzb60WY65XxN23OojEvde7inXOTFPZMIasmATuHOjtR8o4Rsf4UpUBblA+o4IEHDCCBBgwDgYDVR0PAQH/BAQDAgTwMB0GA1UdDgQWBBSiddo8ckTMkYqiq62o1q2ifKLsBDCCAYAGA1UdIwSCAXcwggFzgBRIEK8PXdyZJHb3vw3aS30N2Uzh96GCAUekggFDMIIBPzEYMBYGBSqFA2QBEg0xMDI3NzAwMTk4NzY3MRowGAYIKoUDA4EDAQESDDAwNzcwNzA0OTM4ODELMAkGA1UEBhMCUlUxKTAnBgNVBAgMIDc4INCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMSYwJAYDVQQHDB3QodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszFYMFYGA1UECQxPMTkxMDAyLCDQsy4g0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMsINGD0LsuINCU0L7RgdGC0L7QtdCy0YHQutC+0LPQviDQtC4xNTEmMCQGA1UECgwd0J/QkNCeICLQoNC+0YHRgtC10LvQtdC60L7QvCIxJTAjBgNVBAMMHNCi0LXRgdGC0L7QstGL0Lkg0KPQpiDQoNCi0JqCEHILAVZQABCz6BGkaEvrr/swHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMB0GA1UdIAQWMBQwCAYGKoUDZHEBMAgGBiqFA2RxAjArBgNVHRAEJDAigA8yMDE5MDUyMDExMTcxNVqBDzIwMjAwNTIwMTExNzE1WjCCARAGBSqFA2RwBIIBBTCCAQEMGtCa0YDQuNC/0YLQvtCf0YDQviBDU1AgNC4wDB3QmtGA0LjQv9GC0L7Qn9GA0L4g0KPQpiB2LjIuMAxh0KHQtdGA0YLQuNGE0LjQutCw0YLRiyDRgdC+0L7RgtCy0LXRgtGB0YLQstC40Y8g0KTQodCRINCg0L7RgdGB0LjQuCDQodCkLzEyNC0zMzgwINC+0YIgMTEuMDUuMjAxOAxh0KHQtdGA0YLQuNGE0LjQutCw0YLRiyDRgdC+0L7RgtCy0LXRgtGB0YLQstC40Y8g0KTQodCRINCg0L7RgdGB0LjQuCDQodCkLzEyOC0yOTgzINC+0YIgMTguMTEuMjAxNjAlBgUqhQNkbwQcDBrQmtGA0LjQv9GC0L7Qn9GA0L4gQ1NQIDQuMDBlBgNVHR8EXjBcMFqgWKBWhlRodHRwOi8vY2VydGVucm9sbC50ZXN0Lmdvc3VzbHVnaS5ydS9jZHAvNDgxMGFmMGY1ZGRjOTkyNDc2ZjdiZjBkZGE0YjdkMGRkOTRjZTFmNy5jcmwwVgYIKwYBBQUHAQEESjBIMEYGCCsGAQUFBzAChjpodHRwOi8vY2VydGVucm9sbC50ZXN0Lmdvc3VzbHVnaS5ydS9yYS9jZHAvdGVzdF9jYV9ydGsuY2VyMAoGCCqFAwcBAQMCA0EAo/SBrkS+4CiTj7ojz7uIzjSEyO3hGyB0CFq7SXy1lN94qX1pibq+HOFn9osDYAe9KYm7uBsAFfkUhgiE3oHGiA==</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";*/

       /* //Вид на жительство в РФ
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<ResidencePermitRF>" +
                "<Series>12</Series>" +
                "<Number>1234567</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</ResidencePermitRF>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";
*//*
        //Паспорт моряка
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<SailorPassport>" +
                "<Series>АЯ</Series>" +
                "<Number>1234567</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</SailorPassport>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>MIIHsTCCB16gAwIBAgIQUcu4ABqr9a5B3D/MBeQkIDAKBggqhQMHAQEDAjCCAT8xGDAWBgUqhQNkARINMTAyNzcwMDE5ODc2NzEaMBgGCCqFAwOBAwEBEgwwMDc3MDcwNDkzODgxCzAJBgNVBAYTAlJVMSkwJwYDVQQIDCA3OCDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszEmMCQGA1UEBwwd0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxWDBWBgNVBAkMTzE5MTAwMiwg0LMuINCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzLCDRg9C7LiDQlNC+0YHRgtC+0LXQstGB0LrQvtCz0L4g0LQuMTUxJjAkBgNVBAoMHdCf0JDQniAi0KDQvtGB0YLQtdC70LXQutC+0LwiMSUwIwYDVQQDDBzQotC10YHRgtC+0LLRi9C5INCj0KYg0KDQotCaMB4XDTE5MTIwNTExMDI0OVoXDTIwMTIwNTExMTI0OVowggFPMRowGAYJKoZIhvcNAQkCDAvQotCh0JzQrdCSMzErMCkGCSqGSIb3DQEJARYcVGF0eWFuYS5ub3ZpY2hrb3ZhQHJ0bGFicy5ydTEaMBgGCCqFAwOBAwEBEgwwMDUwNDcwNTM5MjAxGDAWBgUqhQNkARINMTAzNTAwOTU2NzQ1MDEdMBsGA1UECgwU0JDQniAi0KDQoiDQm9Cw0LHRgSIxOzA5BgNVBAkMMtGD0LsuINCf0YDQvtC70LXRgtCw0YDRgdC60LDRjywg0LQuIDIzLCDQutC+0LwgMTAxMRMwEQYDVQQHDArQpdC40LzQutC4MTEwLwYDVQQIDCg1MCDQnNC+0YHQutCy0L7QstGB0LrQsNGPINC+0LHQu9Cw0YHRgtGMMQswCQYDVQQGEwJSVTEdMBsGA1UEAwwU0JDQniAi0KDQoiDQm9Cw0LHRgSIwZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAzmdzBZBPXh3R2CyEBTSF7eN55XLb3bijAbiflGnLemxhIuawVEmAFGv3iNjWcV5nrgHbqFHdyfDOvuKpq9oZ2qOCBBkwggQVMA4GA1UdDwEB/wQEAwIE8DAdBgNVHQ4EFgQUiW5TocF4/TNB0JcX9VRSI4N0BgIwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMFMGCCsGAQUFBwEBBEcwRTBDBggrBgEFBQcwAoY3aHR0cDovL2NlcnRlbnJvbGwudGVzdC5nb3N1c2x1Z2kucnUvY2RwL3Rlc3RfY2FfcnRrLmNlcjAdBgNVHSAEFjAUMAgGBiqFA2RxATAIBgYqhQNkcQIwKwYDVR0QBCQwIoAPMjAxOTEyMDUxMTAyNDlagQ8yMDIwMTIwNTExMDI0OVowggEQBgUqhQNkcASCAQUwggEBDBrQmtGA0LjQv9GC0L7Qn9GA0L4gQ1NQIDQuMAwd0JrRgNC40L/RgtC+0J/RgNC+INCj0KYgdi4yLjAMYdCh0LXRgNGC0LjRhNC40LrQsNGC0Ysg0YHQvtC+0YLQstC10YLRgdGC0LLQuNGPINCk0KHQkSDQoNC+0YHRgdC40Lgg0KHQpC8xMjQtMzM4MCDQvtGCIDExLjA1LjIwMTgMYdCh0LXRgNGC0LjRhNC40LrQsNGC0Ysg0YHQvtC+0YLQstC10YLRgdGC0LLQuNGPINCk0KHQkSDQoNC+0YHRgdC40Lgg0KHQpC8xMjgtMjk4MyDQvtGCIDE4LjExLjIwMTYwJQYFKoUDZG8EHAwa0JrRgNC40L/RgtC+0J/RgNC+IENTUCA0LjAwZQYDVR0fBF4wXDBaoFigVoZUaHR0cDovL2NlcnRlbnJvbGwudGVzdC5nb3N1c2x1Z2kucnUvY2RwLzQ4MTBhZjBmNWRkYzk5MjQ3NmY3YmYwZGRhNGI3ZDBkZDk0Y2UxZjcuY3JsMIIBgAYDVR0jBIIBdzCCAXOAFEgQrw9d3Jkkdve/DdpLfQ3ZTOH3oYIBR6SCAUMwggE/MRgwFgYFKoUDZAESDTEwMjc3MDAxOTg3NjcxGjAYBggqhQMDgQMBARIMMDA3NzA3MDQ5Mzg4MQswCQYDVQQGEwJSVTEpMCcGA1UECAwgNzgg0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxJjAkBgNVBAcMHdCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMVgwVgYDVQQJDE8xOTEwMDIsINCzLiDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQsywg0YPQuy4g0JTQvtGB0YLQvtC10LLRgdC60L7Qs9C+INC0LjE1MSYwJAYDVQQKDB3Qn9CQ0J4gItCg0L7RgdGC0LXQu9C10LrQvtC8IjElMCMGA1UEAwwc0KLQtdGB0YLQvtCy0YvQuSDQo9CmINCg0KLQmoIQcgsBVlAAELPoEaRoS+uv+zAKBggqhQMHAQEDAgNBAGc0p8UJzwTAocj8TuBILo1qDk5u90SjKbjVA4psdoRfwxi21la+FXi+qIgOuthV61qNQbFw2TcTcrtxJvRa8BQ=</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";*/

       /* //Паспорт СССР
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<SovietPassport>" +
                "<Series>I-АЯ</Series>" +
                "<Number>123456</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</SovietPassport>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>MIIHsTCCB16gAwIBAgIQUcu4ABqr9a5B3D/MBeQkIDAKBggqhQMHAQEDAjCCAT8xGDAWBgUqhQNkARINMTAyNzcwMDE5ODc2NzEaMBgGCCqFAwOBAwEBEgwwMDc3MDcwNDkzODgxCzAJBgNVBAYTAlJVMSkwJwYDVQQIDCA3OCDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszEmMCQGA1UEBwwd0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxWDBWBgNVBAkMTzE5MTAwMiwg0LMuINCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzLCDRg9C7LiDQlNC+0YHRgtC+0LXQstGB0LrQvtCz0L4g0LQuMTUxJjAkBgNVBAoMHdCf0JDQniAi0KDQvtGB0YLQtdC70LXQutC+0LwiMSUwIwYDVQQDDBzQotC10YHRgtC+0LLRi9C5INCj0KYg0KDQotCaMB4XDTE5MTIwNTExMDI0OVoXDTIwMTIwNTExMTI0OVowggFPMRowGAYJKoZIhvcNAQkCDAvQotCh0JzQrdCSMzErMCkGCSqGSIb3DQEJARYcVGF0eWFuYS5ub3ZpY2hrb3ZhQHJ0bGFicy5ydTEaMBgGCCqFAwOBAwEBEgwwMDUwNDcwNTM5MjAxGDAWBgUqhQNkARINMTAzNTAwOTU2NzQ1MDEdMBsGA1UECgwU0JDQniAi0KDQoiDQm9Cw0LHRgSIxOzA5BgNVBAkMMtGD0LsuINCf0YDQvtC70LXRgtCw0YDRgdC60LDRjywg0LQuIDIzLCDQutC+0LwgMTAxMRMwEQYDVQQHDArQpdC40LzQutC4MTEwLwYDVQQIDCg1MCDQnNC+0YHQutCy0L7QstGB0LrQsNGPINC+0LHQu9Cw0YHRgtGMMQswCQYDVQQGEwJSVTEdMBsGA1UEAwwU0JDQniAi0KDQoiDQm9Cw0LHRgSIwZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAzmdzBZBPXh3R2CyEBTSF7eN55XLb3bijAbiflGnLemxhIuawVEmAFGv3iNjWcV5nrgHbqFHdyfDOvuKpq9oZ2qOCBBkwggQVMA4GA1UdDwEB/wQEAwIE8DAdBgNVHQ4EFgQUiW5TocF4/TNB0JcX9VRSI4N0BgIwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMFMGCCsGAQUFBwEBBEcwRTBDBggrBgEFBQcwAoY3aHR0cDovL2NlcnRlbnJvbGwudGVzdC5nb3N1c2x1Z2kucnUvY2RwL3Rlc3RfY2FfcnRrLmNlcjAdBgNVHSAEFjAUMAgGBiqFA2RxATAIBgYqhQNkcQIwKwYDVR0QBCQwIoAPMjAxOTEyMDUxMTAyNDlagQ8yMDIwMTIwNTExMDI0OVowggEQBgUqhQNkcASCAQUwggEBDBrQmtGA0LjQv9GC0L7Qn9GA0L4gQ1NQIDQuMAwd0JrRgNC40L/RgtC+0J/RgNC+INCj0KYgdi4yLjAMYdCh0LXRgNGC0LjRhNC40LrQsNGC0Ysg0YHQvtC+0YLQstC10YLRgdGC0LLQuNGPINCk0KHQkSDQoNC+0YHRgdC40Lgg0KHQpC8xMjQtMzM4MCDQvtGCIDExLjA1LjIwMTgMYdCh0LXRgNGC0LjRhNC40LrQsNGC0Ysg0YHQvtC+0YLQstC10YLRgdGC0LLQuNGPINCk0KHQkSDQoNC+0YHRgdC40Lgg0KHQpC8xMjgtMjk4MyDQvtGCIDE4LjExLjIwMTYwJQYFKoUDZG8EHAwa0JrRgNC40L/RgtC+0J/RgNC+IENTUCA0LjAwZQYDVR0fBF4wXDBaoFigVoZUaHR0cDovL2NlcnRlbnJvbGwudGVzdC5nb3N1c2x1Z2kucnUvY2RwLzQ4MTBhZjBmNWRkYzk5MjQ3NmY3YmYwZGRhNGI3ZDBkZDk0Y2UxZjcuY3JsMIIBgAYDVR0jBIIBdzCCAXOAFEgQrw9d3Jkkdve/DdpLfQ3ZTOH3oYIBR6SCAUMwggE/MRgwFgYFKoUDZAESDTEwMjc3MDAxOTg3NjcxGjAYBggqhQMDgQMBARIMMDA3NzA3MDQ5Mzg4MQswCQYDVQQGEwJSVTEpMCcGA1UECAwgNzgg0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxJjAkBgNVBAcMHdCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMVgwVgYDVQQJDE8xOTEwMDIsINCzLiDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQsywg0YPQuy4g0JTQvtGB0YLQvtC10LLRgdC60L7Qs9C+INC0LjE1MSYwJAYDVQQKDB3Qn9CQ0J4gItCg0L7RgdGC0LXQu9C10LrQvtC8IjElMCMGA1UEAwwc0KLQtdGB0YLQvtCy0YvQuSDQo9CmINCg0KLQmoIQcgsBVlAAELPoEaRoS+uv+zAKBggqhQMHAQEDAgNBAGc0p8UJzwTAocj8TuBILo1qDk5u90SjKbjVA4psdoRfwxi21la+FXi+qIgOuthV61qNQbFw2TcTcrtxJvRa8BQ=</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";
*/
        /* //Водительское удостоверение РФ
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<DrivingLicenseRF>" +
                "<Series>4403</Series>" +
                "<Number>123456</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</DrivingLicenseRF>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>MIIHSjCCBvegAwIBAgIQcgsBVlAAT4DpEfJ6Z5xyNzAKBggqhQMHAQEDAjCCAT8xGDAWBgUqhQNkARINMTAyNzcwMDE5ODc2NzEaMBgGCCqFAwOBAwEBEgwwMDc3MDcwNDkzODgxCzAJBgNVBAYTAlJVMSkwJwYDVQQIDCA3OCDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszEmMCQGA1UEBwwd0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxWDBWBgNVBAkMTzE5MTAwMiwg0LMuINCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzLCDRg9C7LiDQlNC+0YHRgtC+0LXQstGB0LrQvtCz0L4g0LQuMTUxJjAkBgNVBAoMHdCf0JDQniAi0KDQvtGB0YLQtdC70LXQutC+0LwiMSUwIwYDVQQDDBzQotC10YHRgtC+0LLRi9C5INCj0KYg0KDQotCaMB4XDTE5MDUyMDExMTcxNVoXDTIwMDUyMDExMjcxNVowgeYxGjAYBggqhQMDgQMBARIMMDA3NzA3MDQ5Mzg4MRgwFgYFKoUDZAESDTEwMjc3MDAxOTg3NjcxKDAmBgNVBAoMH9Cf0JDQniDCq9Cg0L7RgdGC0LXQu9C10LrQvtC8wrsxJjAkBgNVBAcMHdCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMS0wKwYDVQQIDCQ3OCDQsy4g0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxCzAJBgNVBAYTAlJVMSAwHgYDVQQDDBfQotCm0J7QlF/QodCc0K3QkjNf0K3QnDBmMB8GCCqFAwcBAQEBMBMGByqFAwICJAAGCCqFAwcBAQICA0MABEAFxzu1R0MSKe8/eSNtseE8LZMNIqbzb60WY65XxN23OojEvde7inXOTFPZMIasmATuHOjtR8o4Rsf4UpUBblA+o4IEHDCCBBgwDgYDVR0PAQH/BAQDAgTwMB0GA1UdDgQWBBSiddo8ckTMkYqiq62o1q2ifKLsBDCCAYAGA1UdIwSCAXcwggFzgBRIEK8PXdyZJHb3vw3aS30N2Uzh96GCAUekggFDMIIBPzEYMBYGBSqFA2QBEg0xMDI3NzAwMTk4NzY3MRowGAYIKoUDA4EDAQESDDAwNzcwNzA0OTM4ODELMAkGA1UEBhMCUlUxKTAnBgNVBAgMIDc4INCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMSYwJAYDVQQHDB3QodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszFYMFYGA1UECQxPMTkxMDAyLCDQsy4g0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMsINGD0LsuINCU0L7RgdGC0L7QtdCy0YHQutC+0LPQviDQtC4xNTEmMCQGA1UECgwd0J/QkNCeICLQoNC+0YHRgtC10LvQtdC60L7QvCIxJTAjBgNVBAMMHNCi0LXRgdGC0L7QstGL0Lkg0KPQpiDQoNCi0JqCEHILAVZQABCz6BGkaEvrr/swHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMB0GA1UdIAQWMBQwCAYGKoUDZHEBMAgGBiqFA2RxAjArBgNVHRAEJDAigA8yMDE5MDUyMDExMTcxNVqBDzIwMjAwNTIwMTExNzE1WjCCARAGBSqFA2RwBIIBBTCCAQEMGtCa0YDQuNC/0YLQvtCf0YDQviBDU1AgNC4wDB3QmtGA0LjQv9GC0L7Qn9GA0L4g0KPQpiB2LjIuMAxh0KHQtdGA0YLQuNGE0LjQutCw0YLRiyDRgdC+0L7RgtCy0LXRgtGB0YLQstC40Y8g0KTQodCRINCg0L7RgdGB0LjQuCDQodCkLzEyNC0zMzgwINC+0YIgMTEuMDUuMjAxOAxh0KHQtdGA0YLQuNGE0LjQutCw0YLRiyDRgdC+0L7RgtCy0LXRgtGB0YLQstC40Y8g0KTQodCRINCg0L7RgdGB0LjQuCDQodCkLzEyOC0yOTgzINC+0YIgMTguMTEuMjAxNjAlBgUqhQNkbwQcDBrQmtGA0LjQv9GC0L7Qn9GA0L4gQ1NQIDQuMDBlBgNVHR8EXjBcMFqgWKBWhlRodHRwOi8vY2VydGVucm9sbC50ZXN0Lmdvc3VzbHVnaS5ydS9jZHAvNDgxMGFmMGY1ZGRjOTkyNDc2ZjdiZjBkZGE0YjdkMGRkOTRjZTFmNy5jcmwwVgYIKwYBBQUHAQEESjBIMEYGCCsGAQUFBzAChjpodHRwOi8vY2VydGVucm9sbC50ZXN0Lmdvc3VzbHVnaS5ydS9yYS9jZHAvdGVzdF9jYV9ydGsuY2VyMAoGCCqFAwcBAQMCA0EAo/SBrkS+4CiTj7ojz7uIzjSEyO3hGyB0CFq7SXy1lN94qX1pibq+HOFn9osDYAe9KYm7uBsAFfkUhgiE3oHGiA==</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";
*/
         /* //Справка об освобождении
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<ReleaseCertificate>" +
                "<Series>АЯ</Series>" +
                "<Number>123456</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</ReleaseCertificate>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";
*//*
          //Справка об утере паспорта
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<PassportLossCertificate>" +
                "<Series>АЯ</Series>" +
                "<Number>123456</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</PassportLossCertificate>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";*/

     /*       //Справка о регистрации по форме 9
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<Form9Certificate>" +
                "<Series>АЯ</Series>" +
                "<Number>123456</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</Form9Certificate>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";
*/
       /*        //Временное удостоверение личности гражданина РФ по форме 2П
        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:SnilsByAdditionalDataResponse " +
                "xmlns:ns2=\"http://kvs.pfr.com/snils-by-additionalData/1.0.1\" " +
                "xmlns=\"urn://x-artefacts-smev-gov-ru/supplementary/commons/1.0.1\" xmlns:ns3=\"http://common.kvs.pfr.com/1.0.0\">" +
                "<FamilyName>ЛЕОНОВИЧ</FamilyName>" +
                "<FirstName>МАРИНА</FirstName>" +
                "<Patronymic>НИКОЛАЕВНА</Patronymic>" +
                "<ns2:Snils>12803362736</ns2:Snils>" +
                "<ns2:BirthDate>1985-08-26</ns2:BirthDate>" +
                "<ns2:Gender>Female</ns2:Gender>" +
                "<ns2:BirthPlace>" +
                "<ns3:PlaceType>-</ns3:PlaceType>" +
                "<ns3:Settlement>-</ns3:Settlement>" +
                "<ns3:District>-</ns3:District>" +
                "<ns3:Region>город Липецк</ns3:Region>" +
                "<ns3:Country>РФ</ns3:Country>" +
                "</ns2:BirthPlace>" +
                "<TemporaryIdentityCardRF>" +
                "<Series>АЯ</Series>" +
                "<Number>123456</Number>" +
                "<IssueDate>0001-01-01</IssueDate>" +
                "<Issuer>Нет данных</Issuer>" +
                "</TemporaryIdentityCardRF>" +
                "</ns2:SnilsByAdditionalDataResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";
*/
        return testResponseXml;
    }

    @Override
    public String getMvdResponse(String timeBasedUuid) {
        /*String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "\t\t\t\t\t\t\t<ns:response\n" +
                "\t\t\t\t\t\t\t\txmlns:ns=\"urn://ru/mvd/ibd-m/convictions/search/1.0.2\" Id=\"Id1\">\n" +
                "\t\t\t\t\t\t\t\t<ns:records>\n" +
                "<ns:conviction>" +
                "<ns:personalInfo>" +
                "<ns:mainData>" +
                "<ns:lastName>Ванчугов</ns:lastName>" +
                "<ns:firstName>Владимир</ns:firstName>" +
                "<ns:patronymicName>Иванович</ns:patronymicName>" +
                "<ns:birthDate>" +
                "<ns:year>1960</ns:year><ns:month>4</ns:month><ns:day>4</ns:day>" +
                "</ns:birthDate>" +
                "<ns:birthplace>Твой дом - тюрьма!</ns:birthplace>" +
                "</ns:mainData>" +
                "<ns:infoCenter>" +
                "<ns:code>031</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:infoCenter>" +
                "</ns:personalInfo>" +
                "<ns:condemnation>" +
                "<ns:date>2020-01-01</ns:date>" +
                "<ns:enforcer>Орган</ns:enforcer>" +
                "<ns:cause>" +
                "<ns:code>" +
                "<ns:code>123</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:code>" +
                "<ns:article>22</ns:article>" +
                "<ns:part>1</ns:part>" +
                "<ns:paragraph>3</ns:paragraph>" +
                "</ns:cause>" +
                "</ns:condemnation>" +
                "<ns:judgement>" +
                "<ns:type>Арест</ns:type>" +
                "<ns:fine>200</ns:fine>" +
                "<ns:limit>" +
                "<ns:period>" +
                "<ns:years>2</ns:years>" +
                "<ns:months>5</ns:months>" +
                "<ns:days>10</ns:days>" +
                "<ns:hours>5</ns:hours>" +
                "</ns:period>" +
                "</ns:limit>" +
                "</ns:judgement>" +
                "<ns:reQualification>" +
                "<ns:date>2020-07-08</ns:date>" +
                "<ns:enforcer>Орган</ns:enforcer>" +
                "<ns:from>" +
                "<ns:code>" +
                "<ns:code>065</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:code>" +
                "<ns:article>123</ns:article>" +
                "<ns:part>321</ns:part>" +
                "<ns:paragraph>5</ns:paragraph>" +
                "</ns:from>" +
                "<ns:to>" +
                "<ns:code>" +
                "<ns:code>065</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:code>" +
                "<ns:article>123</ns:article>" +
                "<ns:part>321</ns:part>" +
                "<ns:paragraph>5</ns:paragraph>" +
                "</ns:to>" +
                "</ns:reQualification>" +
                "<ns:changingTerm>" +
                "<ns:date>2020-09-08</ns:date>" +
                "<ns:enforcer>Орган</ns:enforcer>" +
                "<ns:period>" +
                "<ns:years>2</ns:years>" +
                "<ns:months>5</ns:months>" +
                "<ns:days>10</ns:days>" +
                "<ns:hours>5</ns:hours>" +
                "</ns:period>" +
                "</ns:changingTerm>" +
                "<ns:changingTerm>" +
                "<ns:date>2019-06-07</ns:date>" +
                "<ns:enforcer>Органы</ns:enforcer>" +
                "<ns:period>" +
                "<ns:years>3</ns:years>" +
                "<ns:months>6</ns:months>" +
                "<ns:days>11</ns:days>" +
                "<ns:hours>4</ns:hours>" +
                "</ns:period>" +
                "</ns:changingTerm>" +
                "<ns:release>" +
                "<ns:date>2020-09-08</ns:date>" +
                "<ns:cause>Причина</ns:cause>" +
                "</ns:release>" +
                "<ns:removeConvictionReasons>Основания</ns:removeConvictionReasons>" +
                "<ns:additionalInfo>Дополнительные данные</ns:additionalInfo>" +
                "</ns:conviction>" +
                "<ns:impeachment>" +
                "<ns:personalInfo>" +
                "<ns:mainData>" +
                "<ns:lastName>Ванчугов</ns:lastName>" +
                "<ns:firstName>Владимир</ns:firstName>" +
                "<ns:patronymicName>Иванович</ns:patronymicName>" +
                "<ns:birthDate>" +
                "<ns:year>1960</ns:year><ns:month>4</ns:month><ns:day>4</ns:day>" +
                "</ns:birthDate>" +
                "<ns:birthplace>Твой дом - тюрьма!</ns:birthplace>" +
                "</ns:mainData>" +
                "<ns:infoCenter>" +
                "<ns:code>031</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:infoCenter>" +
                "</ns:personalInfo>" +
                "<ns:impeachmentInfo>" +
                "<ns:date>2020-09-08</ns:date>" +
                "<ns:enforcer>Орган</ns:enforcer>" +
                "<ns:cause>" +
                "<ns:code>" +
                "<ns:code>123</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:code>" +
                "<ns:article>22</ns:article>" +
                "<ns:part>1</ns:part>" +
                "<ns:paragraph>3</ns:paragraph>" +
                "</ns:cause>" +
                "</ns:impeachmentInfo>" +
                "<ns:judgment>" +
                "<ns:description>Описывание</ns:description>" +
                "<ns:legalInfo>" +
                "<ns:date>2020-09-08</ns:date>" +
                "<ns:enforcer>Орган</ns:enforcer>" +
                "<ns:cause>" +
                "<ns:code>" +
                "<ns:code>123</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:code>" +
                "<ns:article>22</ns:article>" +
                "<ns:part>1</ns:part>" +
                "<ns:paragraph>3</ns:paragraph>" +
                "</ns:cause>" +
                "</ns:legalInfo>" +
                "</ns:judgment>" +
                "<ns:additionalInfo>Инфа</ns:additionalInfo>" +
                "</ns:impeachment>" +
                "<ns:manhunt>" +
                "<ns:personalInfo>" +
                "<ns:mainData>" +
                "<ns:lastName>Ванчугов</ns:lastName>" +
                "<ns:firstName>Владимир</ns:firstName>" +
                "<ns:patronymicName>Иванович</ns:patronymicName>" +
                "<ns:birthDate>" +
                "<ns:year>1960</ns:year><ns:month>4</ns:month><ns:day>4</ns:day>" +
                "</ns:birthDate>" +
                "<ns:birthplace>Твой дом - тюрьма!</ns:birthplace>" +
                "</ns:mainData>" +
                "<ns:infoCenter>" +
                "<ns:code>031</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:infoCenter>" +
                "</ns:personalInfo>" +
                "<ns:manhuntInfo>" +
                "<ns:date>2020-09-08</ns:date>" +
                "<ns:enforcer>Орган</ns:enforcer>" +
                "<ns:cause>" +
                "<ns:code>" +
                "<ns:code>123</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:code>" +
                "<ns:article>22</ns:article>" +
                "<ns:part>1</ns:part>" +
                "<ns:paragraph>3</ns:paragraph>" +
                "</ns:cause>" +
                "</ns:manhuntInfo>" +
                "<ns:additionalInfo>Инфа</ns:additionalInfo>" +
                "</ns:manhunt>" +
                "<ns:exemptionMaterial>" +
                "<ns:personalInfo>" +
                "<ns:mainData>" +
                "<ns:lastName>Ванчугов</ns:lastName>" +
                "<ns:firstName>Владимир</ns:firstName>" +
                "<ns:patronymicName>Иванович</ns:patronymicName>" +
                "<ns:birthDate>" +
                "<ns:year>1960</ns:year><ns:month>4</ns:month><ns:day>4</ns:day>" +
                "</ns:birthDate>" +
                "<ns:birthplace>Твой дом - тюрьма!</ns:birthplace>" +
                "</ns:mainData>" +
                "<ns:infoCenter>" +
                "<ns:code>031</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:infoCenter>" +
                "</ns:personalInfo>" +
                "<ns:denial>" +
                "<ns:date>2020-09-08</ns:date>" +
                "<ns:enforcer>Орган</ns:enforcer>" +
                "<ns:cause>" +
                "<ns:code>" +
                "<ns:code>123</ns:code>" +
                "<ns:value>Что-то там</ns:value>" +
                "</ns:code>" +
                "<ns:article>22</ns:article>" +
                "<ns:part>1</ns:part>" +
                "<ns:paragraph>3</ns:paragraph>" +
                "</ns:cause>" +
                "</ns:denial>" +
                "<ns:reason>" +
                "<ns:description>Описывание</ns:description>" +
                "<ns:cause>" +
                "<ns:code>" +
                "<ns:code>1234444</ns:code>" +
                "<ns:value>Что-то там ещё</ns:value>" +
                "</ns:code>" +
                "<ns:article>223</ns:article>" +
                "<ns:part>122</ns:part>" +
                "<ns:paragraph>344</ns:paragraph>" +
                "</ns:cause>" +
                "</ns:reason>" +
                "</ns:exemptionMaterial>" +
                "<ns:additionalInfo>Инфа</ns:additionalInfo>" +
                "</ns:records>\n" +
                "\t\t\t\t\t\t\t</ns:response>\n" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>MIIHsTCCB16gAwIBAgIQUcu4ABqr9a5B3D/MBeQkIDAKBggqhQMHAQEDAjCCAT8xGDAWBgUqhQNkARINMTAyNzcwMDE5ODc2NzEaMBgGCCqFAwOBAwEBEgwwMDc3MDcwNDkzODgxCzAJBgNVBAYTAlJVMSkwJwYDVQQIDCA3OCDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszEmMCQGA1UEBwwd0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxWDBWBgNVBAkMTzE5MTAwMiwg0LMuINCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzLCDRg9C7LiDQlNC+0YHRgtC+0LXQstGB0LrQvtCz0L4g0LQuMTUxJjAkBgNVBAoMHdCf0JDQniAi0KDQvtGB0YLQtdC70LXQutC+0LwiMSUwIwYDVQQDDBzQotC10YHRgtC+0LLRi9C5INCj0KYg0KDQotCaMB4XDTE5MTIwNTExMDI0OVoXDTIwMTIwNTExMTI0OVowggFPMRowGAYJKoZIhvcNAQkCDAvQotCh0JzQrdCSMzErMCkGCSqGSIb3DQEJARYcVGF0eWFuYS5ub3ZpY2hrb3ZhQHJ0bGFicy5ydTEaMBgGCCqFAwOBAwEBEgwwMDUwNDcwNTM5MjAxGDAWBgUqhQNkARINMTAzNTAwOTU2NzQ1MDEdMBsGA1UECgwU0JDQniAi0KDQoiDQm9Cw0LHRgSIxOzA5BgNVBAkMMtGD0LsuINCf0YDQvtC70LXRgtCw0YDRgdC60LDRjywg0LQuIDIzLCDQutC+0LwgMTAxMRMwEQYDVQQHDArQpdC40LzQutC4MTEwLwYDVQQIDCg1MCDQnNC+0YHQutCy0L7QstGB0LrQsNGPINC+0LHQu9Cw0YHRgtGMMQswCQYDVQQGEwJSVTEdMBsGA1UEAwwU0JDQniAi0KDQoiDQm9Cw0LHRgSIwZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAzmdzBZBPXh3R2CyEBTSF7eN55XLb3bijAbiflGnLemxhIuawVEmAFGv3iNjWcV5nrgHbqFHdyfDOvuKpq9oZ2qOCBBkwggQVMA4GA1UdDwEB/wQEAwIE8DAdBgNVHQ4EFgQUiW5TocF4/TNB0JcX9VRSI4N0BgIwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMFMGCCsGAQUFBwEBBEcwRTBDBggrBgEFBQcwAoY3aHR0cDovL2NlcnRlbnJvbGwudGVzdC5nb3N1c2x1Z2kucnUvY2RwL3Rlc3RfY2FfcnRrLmNlcjAdBgNVHSAEFjAUMAgGBiqFA2RxATAIBgYqhQNkcQIwKwYDVR0QBCQwIoAPMjAxOTEyMDUxMTAyNDlagQ8yMDIwMTIwNTExMDI0OVowggEQBgUqhQNkcASCAQUwggEBDBrQmtGA0LjQv9GC0L7Qn9GA0L4gQ1NQIDQuMAwd0JrRgNC40L/RgtC+0J/RgNC+INCj0KYgdi4yLjAMYdCh0LXRgNGC0LjRhNC40LrQsNGC0Ysg0YHQvtC+0YLQstC10YLRgdGC0LLQuNGPINCk0KHQkSDQoNC+0YHRgdC40Lgg0KHQpC8xMjQtMzM4MCDQvtGCIDExLjA1LjIwMTgMYdCh0LXRgNGC0LjRhNC40LrQsNGC0Ysg0YHQvtC+0YLQstC10YLRgdGC0LLQuNGPINCk0KHQkSDQoNC+0YHRgdC40Lgg0KHQpC8xMjgtMjk4MyDQvtGCIDE4LjExLjIwMTYwJQYFKoUDZG8EHAwa0JrRgNC40L/RgtC+0J/RgNC+IENTUCA0LjAwZQYDVR0fBF4wXDBaoFigVoZUaHR0cDovL2NlcnRlbnJvbGwudGVzdC5nb3N1c2x1Z2kucnUvY2RwLzQ4MTBhZjBmNWRkYzk5MjQ3NmY3YmYwZGRhNGI3ZDBkZDk0Y2UxZjcuY3JsMIIBgAYDVR0jBIIBdzCCAXOAFEgQrw9d3Jkkdve/DdpLfQ3ZTOH3oYIBR6SCAUMwggE/MRgwFgYFKoUDZAESDTEwMjc3MDAxOTg3NjcxGjAYBggqhQMDgQMBARIMMDA3NzA3MDQ5Mzg4MQswCQYDVQQGEwJSVTEpMCcGA1UECAwgNzgg0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxJjAkBgNVBAcMHdCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMVgwVgYDVQQJDE8xOTEwMDIsINCzLiDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQsywg0YPQuy4g0JTQvtGB0YLQvtC10LLRgdC60L7Qs9C+INC0LjE1MSYwJAYDVQQKDB3Qn9CQ0J4gItCg0L7RgdGC0LXQu9C10LrQvtC8IjElMCMGA1UEAwwc0KLQtdGB0YLQvtCy0YvQuSDQo9CmINCg0KLQmoIQcgsBVlAAELPoEaRoS+uv+zAKBggqhQMHAQEDAgNBAGc0p8UJzwTAocj8TuBILo1qDk5u90SjKbjVA4psdoRfwxi21la+FXi+qIgOuthV61qNQbFw2TcTcrtxJvRa8BQ=</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";*/

//        String testResponseXml = "<soap:Envelope\n" +
//                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
//                "\t<soap:Body>\n" +
//                "\t\t<ns2:GetResponseResponse\n" +
//                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
//                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
//                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
//                "\t\t\t<ns2:ResponseMessage>\n" +
//                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
//                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
//                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
//                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
//                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
//                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
//                "\t\t\t\t\t\t\t<ns4:response\n" +
//                "\t\t\t\t\t\t\t\txmlns:ns4=\"urn://ru/mvd/ibd-m/convictions/search/1.0.2\" Id=\"Id1\">\n" +
//                "\t\t\t\t\t\t\t\t<ns4:noRecords/>\n" +
//                "\t\t\t\t\t\t\t</ns4:response>\n" +
//                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
//                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
//                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
//                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
//                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
//                "\t\t\t\t\t\t<ns2:Sender>\n" +
//                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
//                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
//                "\t\t\t\t\t\t</ns2:Sender>\n" +
//                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
//                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
//                "\t\t\t\t\t\t<ns2:Recipient>\n" +
//                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
//                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
//                "\t\t\t\t\t\t</ns2:Recipient>\n" +
//                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
//                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
//                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
//                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
//                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
//                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
//                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
//                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
//                "\t\t\t\t\t\t<ds:Signature\n" +
//                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
//                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
//                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
//                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
//                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
//                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t</ds:Signature>\n" +
//                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
//                "\t\t\t\t</ns2:Response>\n" +
//                "\t\t\t\t<ns2:SMEVSignature>\n" +
//                "\t\t\t\t\t<ds:Signature\n" +
//                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
//                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
//                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
//                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
//                "\t\t\t\t\t\t\t</ds:Reference>\n" +
//                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
//                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
//                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
//                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
//                "\t\t\t\t\t</ds:Signature>\n" +
//                "\t\t\t\t</ns2:SMEVSignature>\n" +
//                "\t\t\t</ns2:ResponseMessage>\n" +
//                "\t\t</ns2:GetResponseResponse>\n" +
//                "\t</soap:Body>\n" +
//                "</soap:Envelope>";

        String testResponseXml = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "        <soap:Body>\n" +
                "            <ns2:GetResponseResponse\n" +
                "                xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "                xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "                xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "                <ns2:ResponseMessage>\n" +
                "                    <ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "                        <ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "                        <ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "                            <ns2:MessageID>ce36aa50-a56e-11ea-8bc7-02420a000551</ns2:MessageID>\n" +
                "                            <ns2:To>eyJzaWQiOjM0NTMxLCJtaWQiOiIwYTM3MTc0Ny1hNTVmLTExZWEtYmViNi02Yjg1ZTgxYzA0NjciLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "                            <MessagePrimaryContent>\n" +
                "                                <ns4:response xmlns:ns4=\"urn://ru/mvd/ibd-m/convictions/search/1.0.2\" xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\" Id=\"F788CC13372A424BA37639F9A33A87C9\">\n" +
                "                                   <ns4:records>\n" +
                "                                       <ns4:additionalInfo>Сведения " +
                //"по судимости/розыску:\n" +
                //"                                       Ошибка форматно-логического контроля:Message/Document/PrivatePerson/SecName(Фамилия) содержит недопустимые символы;Message/Document/PrivatePerson/PlaceOfBirth(code) не заполнен;
                " </ns4:additionalInfo>\n" +
                "                                   </ns4:records>\n" +
                "                                </ns4:response>\n" +
                "                            </MessagePrimaryContent>\n" +
                "                            <ns2:PersonalSignature>\n" +
                "                                <ns5:Signature\n" +
                "                                    xmlns:ns5=\"http://www.w3.org/2000/09/xmldsig#\"\n" +
                "                                    xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" Id=\"3F0ACF55E20C45C495B23A01B3B952B0\">\n" +
                "                                    <ns5:SignedInfo>\n" +
                "                                        <ns5:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ns5:CanonicalizationMethod>\n" +
                "                                        <ns5:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"></ns5:SignatureMethod>\n" +
                "                                        <ns5:Reference URI=\"#B131079C8DBA4130AB59C1B7EEEBC065\">\n" +
                "                                            <ns5:Transforms>\n" +
                "                                                <ns5:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ns5:Transform>\n" +
                "                                                <ns5:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"></ns5:Transform>\n" +
                "                                            </ns5:Transforms>\n" +
                "                                            <ns5:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"></ns5:DigestMethod>\n" +
                "                                            <ns5:DigestValue>lQG8VHjwk+nMH0Kxlmr112KCnTrEnl6E1yNBgYg5r3k=</ns5:DigestValue>\n" +
                "                                        </ns5:Reference>\n" +
                "                                    </ns5:SignedInfo>\n" +
                "                                    <ns5:SignatureValue>ennDwYhGlsiUCUgURVzzEdIGh5/Hc4EIcDd3SuasASOOhG8EQnu08eC0EZdK9WdEAao6APPk0eSPCIK7giGZjw==</ns5:SignatureValue>\n" +
                "                                    <ns5:KeyInfo Id=\"EB2914C536644DE889956710D07ED5B0\">\n" +
                "                                        <ns5:X509Data>\n" +
                "                                            <ns5:X509Certificate>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</ns5:X509Certificate>\n" +
                "                                        </ns5:X509Data>\n" +
                "                                    </ns5:KeyInfo>\n" +
                "                                </ns5:Signature>\n" +
                "                            </ns2:PersonalSignature>\n" +
                "                        </ns2:SenderProvidedResponseData>\n" +
                "                        <ns2:MessageMetadata>\n" +
                "                            <ns2:MessageId>ce36aa50-a56e-11ea-8bc7-02420a000551</ns2:MessageId>\n" +
                "                            <ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "                            <ns2:Sender>\n" +
                "                                <ns2:Mnemonic>MVDR01</ns2:Mnemonic>\n" +
                "                                <ns2:HumanReadableName>Сервисы ИБД</ns2:HumanReadableName>\n" +
                "                            </ns2:Sender>\n" +
                "                            <ns2:SendingTimestamp>2020-06-03T10:49:51.000+03:00</ns2:SendingTimestamp>\n" +
                "                            <ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "                            <ns2:Recipient>\n" +
                "                                <ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "                                <ns2:HumanReadableName>ИСМО</ns2:HumanReadableName>\n" +
                "                            </ns2:Recipient>\n" +
                "                            <ns2:SupplementaryData>\n" +
                "                                <ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "                                <ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "                            </ns2:SupplementaryData>\n" +
                "                            <ns2:DeliveryTimestamp>2020-06-03T10:50:09.934+03:00</ns2:DeliveryTimestamp>\n" +
                "                            <ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "                        </ns2:MessageMetadata>\n" +
                "                        <ns2:SenderInformationSystemSignature>\n" +
                "                            <ns6:Signature\n" +
                "                                xmlns:ns6=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"0008C9052A084A568B3A9F9B3138B62A\">\n" +
                "                                <ns6:SignedInfo>\n" +
                "                                    <ns6:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ns6:CanonicalizationMethod>\n" +
                "                                    <ns6:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"></ns6:SignatureMethod>\n" +
                "                                    <ns6:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "                                        <ns6:Transforms>\n" +
                "                                            <ns6:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ns6:Transform>\n" +
                "                                            <ns6:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"></ns6:Transform>\n" +
                "                                        </ns6:Transforms>\n" +
                "                                        <ns6:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"></ns6:DigestMethod>\n" +
                "                                        <ns6:DigestValue>zc5ErROKRzABaGB8EQWwN9yH6GtvNdut2vmmkzlLl+I=</ns6:DigestValue>\n" +
                "                                    </ns6:Reference>\n" +
                "                                </ns6:SignedInfo>\n" +
                "                                <ns6:SignatureValue>4t3FF+QkW8LYfQnyTHvcf5nBJPMBiqiKP3xYQ14Sf3QgZ3X+XMiDaX0rd36zom4frXNFd/pBLGpGasGYZZF07Q==</ns6:SignatureValue>\n" +
                "                                <ns6:KeyInfo Id=\"0E8EF9FFC96047A0A8089EE9E178642C\">\n" +
                "                                    <ns6:X509Data>\n" +
                "                                        <ns6:X509Certificate>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</ns6:X509Certificate>\n" +
                "                                    </ns6:X509Data>\n" +
                "                                </ns6:KeyInfo>\n" +
                "                            </ns6:Signature>\n" +
                "                        </ns2:SenderInformationSystemSignature>\n" +
                "                    </ns2:Response>\n" +
                "                    <ns2:SMEVSignature>\n" +
                "                        <ds:Signature\n" +
                "                            xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "                            <ds:SignedInfo>\n" +
                "                                <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod>\n" +
                "                                <ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"></ds:SignatureMethod>\n" +
                "                                <ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "                                    <ds:Transforms>\n" +
                "                                        <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform>\n" +
                "                                        <ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"></ds:Transform>\n" +
                "                                    </ds:Transforms>\n" +
                "                                    <ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"></ds:DigestMethod>\n" +
                "                                    <ds:DigestValue>p+W8PkUxluSCSLlDe7aBIzJ+TUoc6KepdSDj9J1V3iM=</ds:DigestValue>\n" +
                "                                </ds:Reference>\n" +
                "                            </ds:SignedInfo>\n" +
                "                            <ds:SignatureValue>Hluaf3M729+E9Sdj4RuX6pUs4gAulBfpB4hJT6+rr4eDMxVe2i4JxX2Ilw8CSCgZqrlGzhLRmUUvnTxU2QHswg==</ds:SignatureValue>\n" +
                "                            <ds:KeyInfo>\n" +
                "                                <ds:X509Data>\n" +
                "                                    <ds:X509Certificate>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</ds:X509Certificate>\n" +
                "                                </ds:X509Data>\n" +
                "                            </ds:KeyInfo>\n" +
                "                        </ds:Signature>\n" +
                "                    </ns2:SMEVSignature>\n" +
                "                </ns2:ResponseMessage>\n" +
                "            </ns2:GetResponseResponse>\n" +
                "        </soap:Body>\n" +
                "    </soap:Envelope>";

        return testResponseXml;
    }


    @Override
    public String getZadolgResponse(String timeBasedUuid) {
        /*String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns1:ZadorgResponse " +
                "xmlns:ns1=\"urn://x-artefacts-fns-zadorg/root/548-04/4.0.4\" " +
                "ИдЗапрос=\"951c9bb05eb94a4da0dd961f69466b16\">" +
                "<ns1:СвЗадолж ДатаСостСв=\"2015-08-13\" ПрЗадолж=\"0\">" +
                "<ns1:ИННФЛ>520203989178</ns1:ИННФЛ></ns1:СвЗадолж></ns1:ZadorgResponse>" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";
*/
//        String testResponseXml = "<soap:Envelope\n" +
//                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
//                "\t<soap:Body>\n" +
//                "\t\t<ns2:GetResponseResponse\n" +
//                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
//                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
//                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
//                "\t\t\t<ns2:ResponseMessage>\n" +
//                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
//                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
//                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
//                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
//                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
//                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
//                "<ns1:ZadorgResponse " +
//                "xmlns:ns1=\"urn://x-artefacts-fns-zadorg/root/548-04/4.0.4\" " +
//                "ИдЗапрос=\"951c9bb05eb94a4da0dd961f69466b16\">" +
//                "<ns1:КодОбраб>11</ns1:КодОбраб>" +
//                "</ns1:ZadorgResponse>" +
//                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
//                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
//                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
//                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
//                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
//                "\t\t\t\t\t\t<ns2:Sender>\n" +
//                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
//                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
//                "\t\t\t\t\t\t</ns2:Sender>\n" +
//                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
//                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
//                "\t\t\t\t\t\t<ns2:Recipient>\n" +
//                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
//                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
//                "\t\t\t\t\t\t</ns2:Recipient>\n" +
//                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
//                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
//                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
//                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
//                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
//                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
//                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
//                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
//                "\t\t\t\t\t\t<ds:Signature\n" +
//                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
//                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
//                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
//                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
//                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
//                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t</ds:Signature>\n" +
//                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
//                "\t\t\t\t</ns2:Response>\n" +
//                "\t\t\t\t<ns2:SMEVSignature>\n" +
//                "\t\t\t\t\t<ds:Signature\n" +
//                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
//                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
//                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
//                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
//                "\t\t\t\t\t\t\t</ds:Reference>\n" +
//                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
//                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
//                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
//                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
//                "\t\t\t\t\t</ds:Signature>\n" +
//                "\t\t\t\t</ns2:SMEVSignature>\n" +
//                "\t\t\t</ns2:ResponseMessage>\n" +
//                "\t\t</ns2:GetResponseResponse>\n" +
//                "\t</soap:Body>\n" +
//                "</soap:Envelope>";

        String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns1:ZadorgResponse" +
                " xmlns:ns1=\"urn://x-artefacts-fns-zadorg/root/548-04/4.0.4\" ИдЗапрос=\"4a507dbc-c033-442d-9f42-2928cb0ed99c\">\n" +
                "                                <ns1:СвЗадолж ДатаСостСв=\"2020-05-25\" ПрЗадолж=\"1\">\n" +
                "                                    <ns1:ИННЮЛ>7707083893</ns1:ИННЮЛ>\n" +
                "                                    <ns1:ПеречНО>\n" +
                "                                        <ns1:КодИФНС>5012</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3454</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3116</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4025</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2032</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5916</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0554</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1722</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7612</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4816</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4027</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3123</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3804</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1513</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5247</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6726</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0326</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0107</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0571</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2370</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5228</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2648</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7527</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0273</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5740</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2373</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6154</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2033</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2807</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4912</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2632</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3019</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0547</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5048</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4705</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1673</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6677</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6681</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3906</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6501</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1106</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1683</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3340</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1841</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0400</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5009</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3917</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6432</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3652</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3435</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3130</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2720</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2643</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6827</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6682</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5474</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1686</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5902</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6226</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6413</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6454</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6025</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2138</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0274</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2209</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4307</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7505</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5483</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5535</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3620</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5075</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5246</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2646</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2207</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5248</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5805</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2372</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2134</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6906</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2235</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3604</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4223</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6174</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7538</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5646</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2649</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5045</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5003</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1322</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6182</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3665</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3328</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2132</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5918</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3444</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4028</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0916</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4712</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6722</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1327</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3851</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6215</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4214</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4312</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2983</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4611</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3252</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6444</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6450</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5948</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5921</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5011</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5260</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2308</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6325</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6908</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5745</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5904</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6225</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5635</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5826</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5959</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2224</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5809</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5475</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1689</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7513</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0309</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0267</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6828</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1831</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0542</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2455</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6683</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2901</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5243</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5038</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3627</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5019</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1512</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2366</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6232</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7148</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5612</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0323</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1828</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3122</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2808</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1218</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1837</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5406</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3525</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2360</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3025</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3126</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0801</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5043</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6230</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2130</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0277</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6612</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7448</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4707</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3664</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1674</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1650</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7321</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6165</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1446</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4205</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6188</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6320</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1675</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7207</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1644</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2210</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4321</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1308</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6195</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5254</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6032</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2634</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1651</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2827</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5110</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7430</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2920</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0603</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>9979</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3455</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5222</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0608</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5020</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2723</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4632</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4316</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1684</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0507</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3811</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5250</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5835</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2133</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3453</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3114</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5034</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0725</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6671</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>8603</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1434</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6829</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2722</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0105</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3629</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3120</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1215</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5933</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2261</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0572</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2377</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7524</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5331</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6330</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3661</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2904</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4614</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2368</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0718</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6714</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1324</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5321</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3666</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5834</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2411</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6030</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2903</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1840</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4727</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3245</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3327</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4824</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5010</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1903</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6446</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6685</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4825</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4813</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5509</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5108</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7459</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4345</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0506</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1310</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4706</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1314</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2371</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5031</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7901</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7153</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0813</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6376</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5906</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2644</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3460</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5249</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7104</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7603</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6820</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6623</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2932</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3663</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3128</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7309</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5336</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6350</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2135</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2137</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4250</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4703</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2801</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2311</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6191</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5018</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7530</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3334</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5802</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5907</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5911</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6193</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6194</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2709</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6732</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6455</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2204</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7452</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>8610</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1328</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5332</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2705</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3253</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5917</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2348</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7736</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2536</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2537</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3601</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5903</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6192</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6438</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6912</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1450</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5024</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6680</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5905</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0716</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7536</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4827</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4330</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2533</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5007</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3316</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6608</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5827</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4704</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3662</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3805</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6449</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0272</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1685</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6234</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5908</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6164</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4101</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6214</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0917</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4811</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1839</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3304</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1326</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0261</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6949</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7453</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1121</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5072</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>8911</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3257</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4177</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1402</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5047</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5022</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4633</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4802</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1838</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5050</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7751</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7907</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5029</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5030</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0276</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6171</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>4001</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>1677</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3812</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6229</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2641</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6952</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5837</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>3332</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7627</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5638</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6324</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5027</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5053</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5017</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>8901</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5074</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2724</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>7151</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>0726</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>5252</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>6725</ns1:КодИФНС>\n" +
                "                                        <ns1:КодИФНС>2804</ns1:КодИФНС>\n" +
                "                                    </ns1:ПеречНО>\n" +
                "                                </ns1:СвЗадолж>\n" +
                "                            </ns1:ZadorgResponse>\n" +
                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>MIIHsTCCB16gAwIBAgIQUcu4ABqr9a5B3D/MBeQkIDAKBggqhQMHAQEDAjCCAT8xGDAWBgUqhQNkARINMTAyNzcwMDE5ODc2NzEaMBgGCCqFAwOBAwEBEgwwMDc3MDcwNDkzODgxCzAJBgNVBAYTAlJVMSkwJwYDVQQIDCA3OCDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszEmMCQGA1UEBwwd0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxWDBWBgNVBAkMTzE5MTAwMiwg0LMuINCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzLCDRg9C7LiDQlNC+0YHRgtC+0LXQstGB0LrQvtCz0L4g0LQuMTUxJjAkBgNVBAoMHdCf0JDQniAi0KDQvtGB0YLQtdC70LXQutC+0LwiMSUwIwYDVQQDDBzQotC10YHRgtC+0LLRi9C5INCj0KYg0KDQotCaMB4XDTE5MTIwNTExMDI0OVoXDTIwMTIwNTExMTI0OVowggFPMRowGAYJKoZIhvcNAQkCDAvQotCh0JzQrdCSMzErMCkGCSqGSIb3DQEJARYcVGF0eWFuYS5ub3ZpY2hrb3ZhQHJ0bGFicy5ydTEaMBgGCCqFAwOBAwEBEgwwMDUwNDcwNTM5MjAxGDAWBgUqhQNkARINMTAzNTAwOTU2NzQ1MDEdMBsGA1UECgwU0JDQniAi0KDQoiDQm9Cw0LHRgSIxOzA5BgNVBAkMMtGD0LsuINCf0YDQvtC70LXRgtCw0YDRgdC60LDRjywg0LQuIDIzLCDQutC+0LwgMTAxMRMwEQYDVQQHDArQpdC40LzQutC4MTEwLwYDVQQIDCg1MCDQnNC+0YHQutCy0L7QstGB0LrQsNGPINC+0LHQu9Cw0YHRgtGMMQswCQYDVQQGEwJSVTEdMBsGA1UEAwwU0JDQniAi0KDQoiDQm9Cw0LHRgSIwZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAzmdzBZBPXh3R2CyEBTSF7eN55XLb3bijAbiflGnLemxhIuawVEmAFGv3iNjWcV5nrgHbqFHdyfDOvuKpq9oZ2qOCBBkwggQVMA4GA1UdDwEB/wQEAwIE8DAdBgNVHQ4EFgQUiW5TocF4/TNB0JcX9VRSI4N0BgIwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMFMGCCsGAQUFBwEBBEcwRTBDBggrBgEFBQcwAoY3aHR0cDovL2NlcnRlbnJvbGwudGVzdC5nb3N1c2x1Z2kucnUvY2RwL3Rlc3RfY2FfcnRrLmNlcjAdBgNVHSAEFjAUMAgGBiqFA2RxATAIBgYqhQNkcQIwKwYDVR0QBCQwIoAPMjAxOTEyMDUxMTAyNDlagQ8yMDIwMTIwNTExMDI0OVowggEQBgUqhQNkcASCAQUwggEBDBrQmtGA0LjQv9GC0L7Qn9GA0L4gQ1NQIDQuMAwd0JrRgNC40L/RgtC+0J/RgNC+INCj0KYgdi4yLjAMYdCh0LXRgNGC0LjRhNC40LrQsNGC0Ysg0YHQvtC+0YLQstC10YLRgdGC0LLQuNGPINCk0KHQkSDQoNC+0YHRgdC40Lgg0KHQpC8xMjQtMzM4MCDQvtGCIDExLjA1LjIwMTgMYdCh0LXRgNGC0LjRhNC40LrQsNGC0Ysg0YHQvtC+0YLQstC10YLRgdGC0LLQuNGPINCk0KHQkSDQoNC+0YHRgdC40Lgg0KHQpC8xMjgtMjk4MyDQvtGCIDE4LjExLjIwMTYwJQYFKoUDZG8EHAwa0JrRgNC40L/RgtC+0J/RgNC+IENTUCA0LjAwZQYDVR0fBF4wXDBaoFigVoZUaHR0cDovL2NlcnRlbnJvbGwudGVzdC5nb3N1c2x1Z2kucnUvY2RwLzQ4MTBhZjBmNWRkYzk5MjQ3NmY3YmYwZGRhNGI3ZDBkZDk0Y2UxZjcuY3JsMIIBgAYDVR0jBIIBdzCCAXOAFEgQrw9d3Jkkdve/DdpLfQ3ZTOH3oYIBR6SCAUMwggE/MRgwFgYFKoUDZAESDTEwMjc3MDAxOTg3NjcxGjAYBggqhQMDgQMBARIMMDA3NzA3MDQ5Mzg4MQswCQYDVQQGEwJSVTEpMCcGA1UECAwgNzgg0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxJjAkBgNVBAcMHdCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMVgwVgYDVQQJDE8xOTEwMDIsINCzLiDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQsywg0YPQuy4g0JTQvtGB0YLQvtC10LLRgdC60L7Qs9C+INC0LjE1MSYwJAYDVQQKDB3Qn9CQ0J4gItCg0L7RgdGC0LXQu9C10LrQvtC8IjElMCMGA1UEAwwc0KLQtdGB0YLQvtCy0YvQuSDQo9CmINCg0KLQmoIQcgsBVlAAELPoEaRoS+uv+zAKBggqhQMHAQEDAgNBAGc0p8UJzwTAocj8TuBILo1qDk5u90SjKbjVA4psdoRfwxi21la+FXi+qIgOuthV61qNQbFw2TcTcrtxJvRa8BQ=</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";

        return testResponseXml;
    }

    @Override
    public String getRejectResponse(String timeBasedUuid) {
        /*String testResponseXml = "<soap:Envelope\n" +
                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "\t<soap:Body>\n" +
                "\t\t<ns2:GetResponseResponse\n" +
                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
                "\t\t\t<ns2:ResponseMessage>\n" +
                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
                "<ns2:RequestRejected>" +
                "<ns2:RejectionReasonCode>NO_DATA</ns2:RejectionReasonCode>" +
                "<ns2:RejectionReasonDescription>Не найдены данные по указанным в запросе параметрам</ns2:RejectionReasonDescription>" +
                "</ns2:RequestRejected>" +
                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
                "\t\t\t\t\t\t<ns2:Sender>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Sender>\n" +
                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
                "\t\t\t\t\t\t<ns2:Recipient>\n" +
                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
                "\t\t\t\t\t\t</ns2:Recipient>\n" +
                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
                "\t\t\t\t</ns2:Response>\n" +
                "\t\t\t\t<ns2:SMEVSignature>\n" +
                "\t\t\t\t\t<ds:Signature\n" +
                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
                "\t\t\t\t\t\t\t</ds:Reference>\n" +
                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";*/

//        String testResponseXml = "<soap:Envelope\n" +
//                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
//                "\t<soap:Body>\n" +
//                "\t\t<ns2:GetResponseResponse\n" +
//                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
//                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
//                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
//                "\t\t\t<ns2:ResponseMessage>\n" +
//                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
//                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
//                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
//                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
//                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
//                //"\t\t\t\t\t\t<MessagePrimaryContent>\n" +
//                "<ns2:RequestRejected>" +
//                "<ns2:RejectionReasonCode>NO_DATA</ns2:RejectionReasonCode>" +
//                "<ns2:RejectionReasonDescription>KVS03203 Нет данных</ns2:RejectionReasonDescription>" +
//                "</ns2:RequestRejected>" +
//                //"\t\t\t\t\t\t</MessagePrimaryContent>\n" +
//                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
//                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
//                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
//                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
//                "\t\t\t\t\t\t<ns2:Sender>\n" +
//                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
//                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
//                "\t\t\t\t\t\t</ns2:Sender>\n" +
//                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
//                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
//                "\t\t\t\t\t\t<ns2:Recipient>\n" +
//                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
//                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
//                "\t\t\t\t\t\t</ns2:Recipient>\n" +
//                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
//                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
//                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
//                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
//                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
//                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
//                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
//                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
//                "\t\t\t\t\t\t<ds:Signature\n" +
//                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
//                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
//                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
//                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
//                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>MIIHSjCCBvegAwIBAgIQcgsBVlAAT4DpEfJ6Z5xyNzAKBggqhQMHAQEDAjCCAT8xGDAWBgUqhQNkARINMTAyNzcwMDE5ODc2NzEaMBgGCCqFAwOBAwEBEgwwMDc3MDcwNDkzODgxCzAJBgNVBAYTAlJVMSkwJwYDVQQIDCA3OCDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszEmMCQGA1UEBwwd0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxWDBWBgNVBAkMTzE5MTAwMiwg0LMuINCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzLCDRg9C7LiDQlNC+0YHRgtC+0LXQstGB0LrQvtCz0L4g0LQuMTUxJjAkBgNVBAoMHdCf0JDQniAi0KDQvtGB0YLQtdC70LXQutC+0LwiMSUwIwYDVQQDDBzQotC10YHRgtC+0LLRi9C5INCj0KYg0KDQotCaMB4XDTE5MDUyMDExMTcxNVoXDTIwMDUyMDExMjcxNVowgeYxGjAYBggqhQMDgQMBARIMMDA3NzA3MDQ5Mzg4MRgwFgYFKoUDZAESDTEwMjc3MDAxOTg3NjcxKDAmBgNVBAoMH9Cf0JDQniDCq9Cg0L7RgdGC0LXQu9C10LrQvtC8wrsxJjAkBgNVBAcMHdCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMS0wKwYDVQQIDCQ3OCDQsy4g0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxCzAJBgNVBAYTAlJVMSAwHgYDVQQDDBfQotCm0J7QlF/QodCc0K3QkjNf0K3QnDBmMB8GCCqFAwcBAQEBMBMGByqFAwICJAAGCCqFAwcBAQICA0MABEAFxzu1R0MSKe8/eSNtseE8LZMNIqbzb60WY65XxN23OojEvde7inXOTFPZMIasmATuHOjtR8o4Rsf4UpUBblA+o4IEHDCCBBgwDgYDVR0PAQH/BAQDAgTwMB0GA1UdDgQWBBSiddo8ckTMkYqiq62o1q2ifKLsBDCCAYAGA1UdIwSCAXcwggFzgBRIEK8PXdyZJHb3vw3aS30N2Uzh96GCAUekggFDMIIBPzEYMBYGBSqFA2QBEg0xMDI3NzAwMTk4NzY3MRowGAYIKoUDA4EDAQESDDAwNzcwNzA0OTM4ODELMAkGA1UEBhMCUlUxKTAnBgNVBAgMIDc4INCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMSYwJAYDVQQHDB3QodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszFYMFYGA1UECQxPMTkxMDAyLCDQsy4g0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMsINGD0LsuINCU0L7RgdGC0L7QtdCy0YHQutC+0LPQviDQtC4xNTEmMCQGA1UECgwd0J/QkNCeICLQoNC+0YHRgtC10LvQtdC60L7QvCIxJTAjBgNVBAMMHNCi0LXRgdGC0L7QstGL0Lkg0KPQpiDQoNCi0JqCEHILAVZQABCz6BGkaEvrr/swHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMB0GA1UdIAQWMBQwCAYGKoUDZHEBMAgGBiqFA2RxAjArBgNVHRAEJDAigA8yMDE5MDUyMDExMTcxNVqBDzIwMjAwNTIwMTExNzE1WjCCARAGBSqFA2RwBIIBBTCCAQEMGtCa0YDQuNC/0YLQvtCf0YDQviBDU1AgNC4wDB3QmtGA0LjQv9GC0L7Qn9GA0L4g0KPQpiB2LjIuMAxh0KHQtdGA0YLQuNGE0LjQutCw0YLRiyDRgdC+0L7RgtCy0LXRgtGB0YLQstC40Y8g0KTQodCRINCg0L7RgdGB0LjQuCDQodCkLzEyNC0zMzgwINC+0YIgMTEuMDUuMjAxOAxh0KHQtdGA0YLQuNGE0LjQutCw0YLRiyDRgdC+0L7RgtCy0LXRgtGB0YLQstC40Y8g0KTQodCRINCg0L7RgdGB0LjQuCDQodCkLzEyOC0yOTgzINC+0YIgMTguMTEuMjAxNjAlBgUqhQNkbwQcDBrQmtGA0LjQv9GC0L7Qn9GA0L4gQ1NQIDQuMDBlBgNVHR8EXjBcMFqgWKBWhlRodHRwOi8vY2VydGVucm9sbC50ZXN0Lmdvc3VzbHVnaS5ydS9jZHAvNDgxMGFmMGY1ZGRjOTkyNDc2ZjdiZjBkZGE0YjdkMGRkOTRjZTFmNy5jcmwwVgYIKwYBBQUHAQEESjBIMEYGCCsGAQUFBzAChjpodHRwOi8vY2VydGVucm9sbC50ZXN0Lmdvc3VzbHVnaS5ydS9yYS9jZHAvdGVzdF9jYV9ydGsuY2VyMAoGCCqFAwcBAQMCA0EAo/SBrkS+4CiTj7ojz7uIzjSEyO3hGyB0CFq7SXy1lN94qX1pibq+HOFn9osDYAe9KYm7uBsAFfkUhgiE3oHGiA==</ds:X509Certificate>\n" +
//                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t</ds:Signature>\n" +
//                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
//                "\t\t\t\t</ns2:Response>\n" +
//                "\t\t\t\t<ns2:SMEVSignature>\n" +
//                "\t\t\t\t\t<ds:Signature\n" +
//                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
//                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
//                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
//                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
//                "\t\t\t\t\t\t\t</ds:Reference>\n" +
//                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
//                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
//                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
//                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
//                "\t\t\t\t\t</ds:Signature>\n" +
//                "\t\t\t\t</ns2:SMEVSignature>\n" +
//                "\t\t\t</ns2:ResponseMessage>\n" +
//                "\t\t</ns2:GetResponseResponse>\n" +
//                "\t</soap:Body>\n" +
//                "</soap:Envelope>";

//        String testResponseXml = "<soap:Envelope\n" +
//                "\txmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
//                "\t<soap:Body>\n" +
//                "\t\t<ns2:GetResponseResponse\n" +
//                "\t\t\txmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"\n" +
//                "\t\t\txmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
//                "\t\t\txmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
//                "\t\t\t<ns2:ResponseMessage>\n" +
//                "\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
//                "\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
//                "\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"SIGNED_BY_CALLER\">\n" +
//                "\t\t\t\t\t\t<ns2:MessageID>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageID>\n" +
//                "\t\t\t\t\t\t<ns2:To>eyJzaWQiOjMxNzU1LCJtaWQiOiIwZjYyMWI2MC00ZjA1LTExZWEtYjMxMy0yN2E1YTZjMzYwZDEiLCJlb2wiOjAsInNsYyI6InJ1X212ZF9pYmQtbV9jb252aWN0aW9uc19zZWFyY2hfMS4wLjJfcmVxdWVzdCIsIm1ubSI6IjQ4MDEwMiJ9</ns2:To>\n" +
//                "\t\t\t\t\t\t<MessagePrimaryContent>\n" +
//                "<rs:ResponseDocument xmlns:rs=\"urn://x-artefacts-fns-SRCHIS/082-2/4.0.1\" ИдЗапросФНС=\"00000000000001852923\">" +
//                "   <rs:КодОбр>83</rs:КодОбр>" +
//                "</rs:ResponseDocument>" +
//                "\t\t\t\t\t\t</MessagePrimaryContent>\n" +
//                "\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
//                "\t\t\t\t\t<ns2:MessageMetadata>\n" +
//                "\t\t\t\t\t\t<ns2:MessageId>19ceb791-4f05-11ea-9be6-fa163e24a723</ns2:MessageId>\n" +
//                "\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
//                "\t\t\t\t\t\t<ns2:Sender>\n" +
//                "\t\t\t\t\t\t\t<ns2:Mnemonic>emu</ns2:Mnemonic>\n" +
//                "\t\t\t\t\t\t\t<ns2:HumanReadableName>emu</ns2:HumanReadableName>\n" +
//                "\t\t\t\t\t\t</ns2:Sender>\n" +
//                "\t\t\t\t\t\t<ns2:SendingTimestamp>2020-02-14T11:36:31.000+03:00</ns2:SendingTimestamp>\n" +
//                "\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
//                "\t\t\t\t\t\t<ns2:Recipient>\n" +
//                "\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
//                "\t\t\t\t\t\t\t<ns2:HumanReadableName>ИС МО</ns2:HumanReadableName>\n" +
//                "\t\t\t\t\t\t</ns2:Recipient>\n" +
//                "\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
//                "\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
//                "\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
//                "\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
//                "\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-02-14T11:38:10.150+03:00</ns2:DeliveryTimestamp>\n" +
//                "\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
//                "\t\t\t\t\t</ns2:MessageMetadata>\n" +
//                "\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
//                "\t\t\t\t\t\t<ds:Signature\n" +
//                "\t\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
//                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_CALLER\">\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>rQ7hbHnfo5z6P6DWIcV/aAQFcqOpb8rsCbys2ownU6o=</ds:DigestValue>\n" +
//                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
//                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:SignatureValue>RDmiG375mVM/l7fGvNlHD9UylZAO2nJiZT+2RNaOHPl9UDoE2NMRi4RAcVP3R8m7QhCyUibB7fMgcmtB6Lrdtg==</ds:SignatureValue>\n" +
//                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>MIIHSjCCBvegAwIBAgIQcgsBVlAAT4DpEfJ6Z5xyNzAKBggqhQMHAQEDAjCCAT8xGDAWBgUqhQNkARINMTAyNzcwMDE5ODc2NzEaMBgGCCqFAwOBAwEBEgwwMDc3MDcwNDkzODgxCzAJBgNVBAYTAlJVMSkwJwYDVQQIDCA3OCDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszEmMCQGA1UEBwwd0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxWDBWBgNVBAkMTzE5MTAwMiwg0LMuINCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzLCDRg9C7LiDQlNC+0YHRgtC+0LXQstGB0LrQvtCz0L4g0LQuMTUxJjAkBgNVBAoMHdCf0JDQniAi0KDQvtGB0YLQtdC70LXQutC+0LwiMSUwIwYDVQQDDBzQotC10YHRgtC+0LLRi9C5INCj0KYg0KDQotCaMB4XDTE5MDUyMDExMTcxNVoXDTIwMDUyMDExMjcxNVowgeYxGjAYBggqhQMDgQMBARIMMDA3NzA3MDQ5Mzg4MRgwFgYFKoUDZAESDTEwMjc3MDAxOTg3NjcxKDAmBgNVBAoMH9Cf0JDQniDCq9Cg0L7RgdGC0LXQu9C10LrQvtC8wrsxJjAkBgNVBAcMHdCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMS0wKwYDVQQIDCQ3OCDQsy4g0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxCzAJBgNVBAYTAlJVMSAwHgYDVQQDDBfQotCm0J7QlF/QodCc0K3QkjNf0K3QnDBmMB8GCCqFAwcBAQEBMBMGByqFAwICJAAGCCqFAwcBAQICA0MABEAFxzu1R0MSKe8/eSNtseE8LZMNIqbzb60WY65XxN23OojEvde7inXOTFPZMIasmATuHOjtR8o4Rsf4UpUBblA+o4IEHDCCBBgwDgYDVR0PAQH/BAQDAgTwMB0GA1UdDgQWBBSiddo8ckTMkYqiq62o1q2ifKLsBDCCAYAGA1UdIwSCAXcwggFzgBRIEK8PXdyZJHb3vw3aS30N2Uzh96GCAUekggFDMIIBPzEYMBYGBSqFA2QBEg0xMDI3NzAwMTk4NzY3MRowGAYIKoUDA4EDAQESDDAwNzcwNzA0OTM4ODELMAkGA1UEBhMCUlUxKTAnBgNVBAgMIDc4INCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMSYwJAYDVQQHDB3QodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszFYMFYGA1UECQxPMTkxMDAyLCDQsy4g0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMsINGD0LsuINCU0L7RgdGC0L7QtdCy0YHQutC+0LPQviDQtC4xNTEmMCQGA1UECgwd0J/QkNCeICLQoNC+0YHRgtC10LvQtdC60L7QvCIxJTAjBgNVBAMMHNCi0LXRgdGC0L7QstGL0Lkg0KPQpiDQoNCi0JqCEHILAVZQABCz6BGkaEvrr/swHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMB0GA1UdIAQWMBQwCAYGKoUDZHEBMAgGBiqFA2RxAjArBgNVHRAEJDAigA8yMDE5MDUyMDExMTcxNVqBDzIwMjAwNTIwMTExNzE1WjCCARAGBSqFA2RwBIIBBTCCAQEMGtCa0YDQuNC/0YLQvtCf0YDQviBDU1AgNC4wDB3QmtGA0LjQv9GC0L7Qn9GA0L4g0KPQpiB2LjIuMAxh0KHQtdGA0YLQuNGE0LjQutCw0YLRiyDRgdC+0L7RgtCy0LXRgtGB0YLQstC40Y8g0KTQodCRINCg0L7RgdGB0LjQuCDQodCkLzEyNC0zMzgwINC+0YIgMTEuMDUuMjAxOAxh0KHQtdGA0YLQuNGE0LjQutCw0YLRiyDRgdC+0L7RgtCy0LXRgtGB0YLQstC40Y8g0KTQodCRINCg0L7RgdGB0LjQuCDQodCkLzEyOC0yOTgzINC+0YIgMTguMTEuMjAxNjAlBgUqhQNkbwQcDBrQmtGA0LjQv9GC0L7Qn9GA0L4gQ1NQIDQuMDBlBgNVHR8EXjBcMFqgWKBWhlRodHRwOi8vY2VydGVucm9sbC50ZXN0Lmdvc3VzbHVnaS5ydS9jZHAvNDgxMGFmMGY1ZGRjOTkyNDc2ZjdiZjBkZGE0YjdkMGRkOTRjZTFmNy5jcmwwVgYIKwYBBQUHAQEESjBIMEYGCCsGAQUFBzAChjpodHRwOi8vY2VydGVucm9sbC50ZXN0Lmdvc3VzbHVnaS5ydS9yYS9jZHAvdGVzdF9jYV9ydGsuY2VyMAoGCCqFAwcBAQMCA0EAo/SBrkS+4CiTj7ojz7uIzjSEyO3hGyB0CFq7SXy1lN94qX1pibq+HOFn9osDYAe9KYm7uBsAFfkUhgiE3oHGiA==</ds:X509Certificate>\n" +
//                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t</ds:Signature>\n" +
//                "\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
//                "\t\t\t\t</ns2:Response>\n" +
//                "\t\t\t\t<ns2:SMEVSignature>\n" +
//                "\t\t\t\t\t<ds:Signature\n" +
//                "\t\t\t\t\t\txmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
//                "\t\t\t\t\t\t<ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
//                "\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
//                "\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:DigestValue>e3RVaKkWTM97G0AT4fTQgjwQIkmjYAm5KVDeRFpVA2A=</ds:DigestValue>\n" +
//                "\t\t\t\t\t\t\t</ds:Reference>\n" +
//                "\t\t\t\t\t\t</ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t<ds:SignatureValue>WRZpqEFy/JO6E9fo2DjKl+1JJSIJd/KlFIVBTK1NG7+tKLnQ7ZeUeK8MFvriIomNGjPbI73QIHNJj88yTkKICg==</ds:SignatureValue>\n" +
//                "\t\t\t\t\t\t<ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
//                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
//                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
//                "\t\t\t\t\t</ds:Signature>\n" +
//                "\t\t\t\t</ns2:SMEVSignature>\n" +
//                "\t\t\t</ns2:ResponseMessage>\n" +
//                "\t\t</ns2:GetResponseResponse>\n" +
//                "\t</soap:Body>\n" +
//                "</soap:Envelope>";

//        String testResponseXml = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
//                "\t\t<soap:Body>\n" +
//                "\t\t\t<ns2:GetResponseResponse xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\" xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\" xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\">\n" +
//                "\t\t\t\t<ns2:ResponseMessage>\n" +
//                "\t\t\t\t\t<ns2:Response Id=\"SIGNED_BY_SMEV\">\n" +
//                "\t\t\t\t\t\t<ns2:OriginalMessageId>" + timeBasedUuid + "</ns2:OriginalMessageId>\n" +
//                "\t\t\t\t\t\t<ns2:SenderProvidedResponseData Id=\"Icd820751-9fd6-11ea-af75-0050568353ed\">\n" +
//                "\t\t\t\t\t\t\t<ns2:MessageID>cd820750-9fd6-11ea-af75-0050568353ed</ns2:MessageID>\n" +
//                "\t\t\t\t\t\t\t<ns2:To>eyJzaWQiOjM0NTMxLCJtaWQiOiJiNDRlYzNlMC05ZmQ2LTExZWEtOWExNS0wMDUwNTZiYjQ2MGMiLCJlb2wiOjAsInNsYyI6InJvc2them5hLnJ1X2dpc2dtcF94c2Rfc2VydmljZXNfZXhwb3J0LWNoYXJnZXNfMi4wLjFfRXhwb3J0Q2hhcmdlc1JlcXVlc3QiLCJtbm0iOiI0ODAxMDIifQ==</ns2:To>\n" +
//                "\t\t\t\t\t\t\t<ns2:RequestRejected>\n" +
//                "\t\t\t\t\t\t\t\t<ns2:RejectionReasonCode>NO_DATA</ns2:RejectionReasonCode>\n" +
//                "\t\t\t\t\t\t\t\t<ns2:RejectionReasonDescription>Данные отсутствуют</ns2:RejectionReasonDescription>\n" +
//                "\t\t\t\t\t\t\t</ns2:RequestRejected>\n" +
//                "\t\t\t\t\t\t</ns2:SenderProvidedResponseData>\n" +
//                "\t\t\t\t\t\t<ns2:MessageMetadata>\n" +
//                "\t\t\t\t\t\t\t<ns2:MessageId>cd820750-9fd6-11ea-af75-0050568353ed</ns2:MessageId>\n" +
//                "\t\t\t\t\t\t\t<ns2:MessageType>RESPONSE</ns2:MessageType>\n" +
//                "\t\t\t\t\t\t\t<ns2:Sender>\n" +
//                "\t\t\t\t\t\t\t\t<ns2:Mnemonic>RKZN02_3S</ns2:Mnemonic>\n" +
//                "\t\t\t\t\t\t\t\t<ns2:HumanReadableName>ГИС ГМП</ns2:HumanReadableName>\n" +
//                "\t\t\t\t\t\t\t</ns2:Sender>\n" +
//                "\t\t\t\t\t\t\t<ns2:SendingTimestamp>2020-05-27T07:59:10.000+03:00</ns2:SendingTimestamp>\n" +
//                "\t\t\t\t\t\t\t<ns2:DestinationName>unknown</ns2:DestinationName>\n" +
//                "\t\t\t\t\t\t\t<ns2:Recipient>\n" +
//                "\t\t\t\t\t\t\t\t<ns2:Mnemonic>480102</ns2:Mnemonic>\n" +
//                "\t\t\t\t\t\t\t\t<ns2:HumanReadableName>ИСМО</ns2:HumanReadableName>\n" +
//                "\t\t\t\t\t\t\t</ns2:Recipient>\n" +
//                "\t\t\t\t\t\t\t<ns2:SupplementaryData>\n" +
//                "\t\t\t\t\t\t\t\t<ns2:DetectedContentTypeName>not detected</ns2:DetectedContentTypeName>\n" +
//                "\t\t\t\t\t\t\t\t<ns2:InteractionType>NotDetected</ns2:InteractionType>\n" +
//                "\t\t\t\t\t\t\t</ns2:SupplementaryData>\n" +
//                "\t\t\t\t\t\t\t<ns2:DeliveryTimestamp>2020-05-27T07:59:19.047+03:00</ns2:DeliveryTimestamp>\n" +
//                "\t\t\t\t\t\t\t<ns2:Status>responseIsDelivered</ns2:Status>\n" +
//                "\t\t\t\t\t\t</ns2:MessageMetadata>\n" +
//                "\t\t\t\t\t\t<ns2:SenderInformationSystemSignature>\n" +
//                "\t\t\t\t\t\t\t<Signature:Signature xmlns:Signature=\"http://www.w3.org/2000/09/xmldsig#\" xmlns=\"http://www.w3.org/2000/09/xmldsig#\" xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.2\" xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.2\" Id=\"Id-sig-e07abbf5977fe8f5a952e7fcf0b3fe62b18a\">\n" +
//                "\t\t\t\t\t\t\t\t<SignedInfo>\n" +
//                "\t\t\t\t\t\t\t\t\t<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<Reference Id=\"Id-dataref-d5c970187445f9a341d2c3762db0f124bc95\" URI=\"#Icd820751-9fd6-11ea-af75-0050568353ed\">\n" +
//                "\t\t\t\t\t\t\t\t\t\t<Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t\t\t<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t\t\t<Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t\t</Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<DigestValue>VLAXP1l+YRvkCN8MjQQQ5qe4FMHdK/1aNMF/uZiIvB0=</DigestValue>\n" +
//                "\t\t\t\t\t\t\t\t\t</Reference>\n" +
//                "\t\t\t\t\t\t\t\t</SignedInfo>\n" +
//                "\t\t\t\t\t\t\t\t<SignatureValue>XL7roFlLC8O0WXblj+A8Eg7FUst7eSo9g5Pe6bWMtiNU7P+mmLcTufwVtj/N+AMd\n" +
//                "1O+IlCc2pNlMbqbQgafd2Q==</SignatureValue>\n" +
//                "\t\t\t\t\t\t\t\t<KeyInfo Id=\"Id-keyinfo-da1fad3d750f970a9da2856ec41bf5a8993a\">\n" +
//                "\t\t\t\t\t\t\t\t\t<X509Data>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<X509Certificate>MIIIeTCCCCagAwIBAgIUVhpesPhMDdLrEyXhai/hlNbP2hkwCgYIKoUDBwEBAwIw\n" +
//                "ggFtMSAwHgYJKoZIhvcNAQkBFhF1Y19ma0Byb3NrYXpuYS5ydTEZMBcGA1UECAwQ\n" +
//                "0LMuINCc0L7RgdC60LLQsDEaMBgGCCqFAwOBAwEBEgwwMDc3MTA1Njg3NjAxGDAW\n" +
//                "BgUqhQNkARINMTA0Nzc5NzAxOTgzMDFgMF4GA1UECQxX0JHQvtC70YzRiNC+0Lkg\n" +
//                "0JfQu9Cw0YLQvtGD0YHRgtC40L3RgdC60LjQuSDQv9C10YDQtdGD0LvQvtC6LCDQ\n" +
//                "tC4gNiwg0YHRgtGA0L7QtdC90LjQtSAxMRUwEwYDVQQHDAzQnNC+0YHQutCy0LAx\n" +
//                "CzAJBgNVBAYTAlJVMTgwNgYDVQQKDC/QpNC10LTQtdGA0LDQu9GM0L3QvtC1INC6\n" +
//                "0LDQt9C90LDRh9C10LnRgdGC0LLQvjE4MDYGA1UEAwwv0KTQtdC00LXRgNCw0LvR\n" +
//                "jNC90L7QtSDQutCw0LfQvdCw0YfQtdC50YHRgtCy0L4wHhcNMjAwNDIyMDczOTI1\n" +
//                "WhcNMjEwNzIyMDczOTI1WjCCAd0xGjAYBggqhQMDgQMBARIMMDA3NzEwNTY4NzYw\n" +
//                "MRgwFgYFKoUDZAESDTEwNDc3OTcwMTk4MzAxXjBcBgNVBAkMVdCR0L7Qu9GM0YjQ\n" +
//                "vtC5INCX0LvQsNGC0L7Rg9GB0YLQuNC90YHQutC40Lkg0L/QtdGA0LXRg9C70L7Q\n" +
//                "uiDQtC4gNiDRgdGC0YDQvtC10L3QuNC1IDExHzAdBgkqhkiG9w0BCQEWEGlzZmtA\n" +
//                "cm9za2F6bmEucnUxCzAJBgNVBAYTAlJVMRkwFwYDVQQIDBDQsy4g0JzQvtGB0LrQ\n" +
//                "stCwMRUwEwYDVQQHDAzQnNC+0YHQutCy0LAxODA2BgNVBAoML9Ck0LXQtNC10YDQ\n" +
//                "sNC70YzQvdC+0LUg0LrQsNC30L3QsNGH0LXQudGB0YLQstC+MVkwVwYDVQQLDFDQ\n" +
//                "o9C/0YDQsNCy0LvQtdC90LjQtSDQuNC90YTQvtGA0LzQsNGG0LjQvtC90L3QvtC5\n" +
//                "INC40L3RhNGA0LDRgdGC0YDRg9C60YLRg9GA0L7QuTEWMBQGCSqGSIb3DQEJAgwH\n" +
//                "Z2lzX2dtcDE4MDYGA1UEAwwv0KTQtdC00LXRgNCw0LvRjNC90L7QtSDQutCw0LfQ\n" +
//                "vdCw0YfQtdC50YHRgtCy0L4wZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMH\n" +
//                "AQECAgNDAARAm3nXtEHR+RBONsxmy9XPB2qT4wLQtWAb+FjHWP68JssXSDmLTY61\n" +
//                "Sq2RpSMY9Ydkby72NaF/r31WtPZ9qCahX6OCBCEwggQdMAwGA1UdEwEB/wQCMAAw\n" +
//                "HQYDVR0gBBYwFDAIBgYqhQNkcQEwCAYGKoUDZHECMEgGBSqFA2RvBD8MPSLQmtGA\n" +
//                "0LjQv9GC0L4t0J/RgNC+IENTUCIgdi40LjAgKNC40YHQv9C+0LvQvdC10L3QuNC1\n" +
//                "IDItQmFzZSkwggFkBgUqhQNkcASCAVkwggFVDEci0JrRgNC40L/RgtC+0J/RgNC+\n" +
//                "IENTUCIg0LLQtdGA0YHQuNGPIDQuMCAo0LjRgdC/0L7Qu9C90LXQvdC40LUgMi1C\n" +
//                "YXNlKQxo0J/RgNC+0LPRgNCw0LzQvNC90L4t0LDQv9C/0LDRgNCw0YLQvdGL0Lkg\n" +
//                "0LrQvtC80L/Qu9C10LrRgSDCq9Cu0L3QuNGB0LXRgNGCLdCT0J7QodCiwrsuINCS\n" +
//                "0LXRgNGB0LjRjyAzLjAMT9Ch0LXRgNGC0LjRhNC40LrQsNGCINGB0L7QvtGC0LLQ\n" +
//                "tdGC0YHRgtCy0LjRjyDihJYg0KHQpC8xMjQtMzM4MCDQvtGCIDExLjA1LjIwMTgM\n" +
//                "T9Ch0LXRgNGC0LjRhNC40LrQsNGCINGB0L7QvtGC0LLQtdGC0YHRgtCy0LjRjyDi\n" +
//                "hJYg0KHQpC8xMjgtMzU4MSDQvtGCIDIwLjEyLjIwMTgwDgYDVR0PAQH/BAQDAgP4\n" +
//                "MBMGA1UdJQQMMAoGCCsGAQUFBwMDMCsGA1UdEAQkMCKADzIwMjAwNDIyMDczOTI1\n" +
//                "WoEPMjAyMTA3MjIwNzM5MjVaMIIBXwYDVR0jBIIBVjCCAVKAFNBklm1yQOtYfSR/\n" +
//                "uyBbz8OObHrUoYIBLKSCASgwggEkMR4wHAYJKoZIhvcNAQkBFg9kaXRAbWluc3Z5\n" +
//                "YXoucnUxCzAJBgNVBAYTAlJVMRgwFgYDVQQIDA83NyDQnNC+0YHQutCy0LAxGTAX\n" +
//                "BgNVBAcMENCzLiDQnNC+0YHQutCy0LAxLjAsBgNVBAkMJdGD0LvQuNGG0LAg0KLQ\n" +
//                "stC10YDRgdC60LDRjywg0LTQvtC8IDcxLDAqBgNVBAoMI9Cc0LjQvdC60L7QvNGB\n" +
//                "0LLRj9C30Ywg0KDQvtGB0YHQuNC4MRgwFgYFKoUDZAESDTEwNDc3MDIwMjY3MDEx\n" +
//                "GjAYBggqhQMDgQMBARIMMDA3NzEwNDc0Mzc1MSwwKgYDVQQDDCPQnNC40L3QutC+\n" +
//                "0LzRgdCy0Y/Qt9GMINCg0L7RgdGB0LjQuIIKYqt5lQAAAAADtjBoBgNVHR8EYTBf\n" +
//                "MC6gLKAqhihodHRwOi8vY3JsLnJvc2them5hLnJ1L2NybC91Y2ZrXzIwMjAuY3Js\n" +
//                "MC2gK6AphidodHRwOi8vY3JsLmZzZmsubG9jYWwvY3JsL3VjZmtfMjAyMC5jcmww\n" +
//                "HQYDVR0OBBYEFAX4obUNaKWui9FanMogaS5s793LMAoGCCqFAwcBAQMCA0EAxldz\n" +
//                "yNHaALDLkxG6XbWNIlx3p93etQpGx1Z0MNjy/Kl4JhyLsHux61hA9XQa2mq2hGLB\n" +
//                "mpfZdqzlVbcBiQT2Gw==</X509Certificate>\n" +
//                "\t\t\t\t\t\t\t\t\t</X509Data>\n" +
//                "\t\t\t\t\t\t\t\t</KeyInfo>\n" +
//                "\t\t\t\t\t\t\t</Signature:Signature>\n" +
//                "\t\t\t\t\t\t</ns2:SenderInformationSystemSignature>\n" +
//                "\t\t\t\t\t</ns2:Response>\n" +
//                "\t\t\t\t\t<ns2:SMEVSignature>\n" +
//                "\t\t\t\t\t\t<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
//                "\t\t\t\t\t\t\t<ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t<ds:Reference URI=\"#SIGNED_BY_SMEV\">\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t\t<ds:Transform Algorithm=\"urn://smev-gov-ru/xmldsig/transform\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t</ds:Transforms>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\"/>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:DigestValue>G40mcR5/XCSG/GJ+L8JZsN/nKCqVzM3RlEC5POJrl4c=</ds:DigestValue>\n" +
//                "\t\t\t\t\t\t\t\t</ds:Reference>\n" +
//                "\t\t\t\t\t\t\t</ds:SignedInfo>\n" +
//                "\t\t\t\t\t\t\t<ds:SignatureValue>xHLZbgeH28x1DMWDWgaZpt3OFTVNB9KQocnRsAvoUNJyw293Sc4YLOj9P/3WHFUunF+XNAqJ0W5rKVJFelnfbw==</ds:SignatureValue>\n" +
//                "\t\t\t\t\t\t\t<ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t\t\t<ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
//                "\t\t\t\t\t\t\t\t</ds:X509Data>\n" +
//                "\t\t\t\t\t\t\t</ds:KeyInfo>\n" +
//                "\t\t\t\t\t\t</ds:Signature>\n" +
//                "\t\t\t\t\t</ns2:SMEVSignature>\n" +
//                "\t\t\t\t</ns2:ResponseMessage>\n" +
//                "\t\t\t</ns2:GetResponseResponse>\n" +
//                "\t\t</soap:Body>\n" +
//                "\t</soap:Envelope>";

        String testResponseXml = "<soap:Envelope\n" +
                "    xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n" +
                "    <soap:Body>\n" +
                "        <ns2:GetResponseResponse\n" +
                "            xmlns:ns3=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/faults/1.1\"\n" +
                "            xmlns:ns2=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/1.1\"\n" +
                "            xmlns=\"urn://x-artefacts-smev-gov-ru/services/message-exchange/types/basic/1.1\"/>\n" +
                "        </soap:Body>\n" +
                "    </soap:Envelope>";

        return testResponseXml;
    }

    /*"\t\t\t\t\t\t\t<ns:response\n" +
                "\t\t\t\t\t\t\t\txmlns:ns=\"urn://ru/mvd/ibd-m/convictions/search/1.0.2\" Id=\"Id1\">\n" +
    "\t\t\t\t\t\t\t\t<ns:records>\n" +
            "<ns:conviction>" +
            "<ns:personalInfo>" +
            "<ns:mainData>" +
            "<ns:lastName>Ванчугов</ns:lastName>" +
            "<ns:firstName>Владимир</ns:firstName>" +
            "<ns:patronymicName>Иванович</ns:patronymicName>" +
            "<ns:birthDate>" +
            "<ns:year>1960</ns:year><ns:month>4</ns:month><ns:day>4</ns:day>" +
            "</ns:birthDate>" +
            "<ns:birthplace>Твой дом - тюрьма!</ns:birthplace>" +
            "</ns:mainData>" +
            "<ns:infoCenter>" +
            "<ns:code>031</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:infoCenter>" +
            "</ns:personalInfo>" +
            "<ns:condemnation>" +
            "<ns:date>2020-01-01</ns:date>" +
            "<ns:enforcer>Орган</ns:enforcer>" +
            "<ns:cause>" +
            "<ns:code>" +
            "<ns:code>123</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:code>" +
            "<ns:article>22</ns:article>" +
            "<ns:part>1</ns:part>" +
            "<ns:paragraph>3</ns:paragraph>" +
            "</ns:cause>" +
            "</ns:condemnation>" +
            "<ns:judgement>" +
            "<ns:type>Арест</ns:type>" +
            "<ns:fine>200</ns:fine>" +
            "<ns:limit>" +
            "<ns:period>" +
            "<ns:years>2</ns:years>" +
            "<ns:months>5</ns:months>" +
            "<ns:days>10</ns:days>" +
            "<ns:hours>5</ns:hours>" +
            "</ns:period>" +
            "</ns:limit>" +
            "</ns:judgement>" +
            "<ns:reQualification>" +
            "<ns:date>2020-07-08</ns:date>" +
            "<ns:enforcer>Орган</ns:enforcer>" +
            "<ns:from>" +
            "<ns:code>" +
            "<ns:code>065</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:code>" +
            "<ns:article>123</ns:article>" +
            "<ns:part>321</ns:part>" +
            "<ns:paragraph>5</ns:paragraph>" +
            "</ns:from>" +
            "<ns:to>" +
            "<ns:code>" +
            "<ns:code>065</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:code>" +
            "<ns:article>123</ns:article>" +
            "<ns:part>321</ns:part>" +
            "<ns:paragraph>5</ns:paragraph>" +
            "</ns:to>" +
            "</ns:reQualification>" +
            "<ns:changingTerm>" +
            "<ns:date>2020-09-08</ns:date>" +
            "<ns:enforcer>Орган</ns:enforcer>" +
            "<ns:period>" +
            "<ns:years>2</ns:years>" +
            "<ns:months>5</ns:months>" +
            "<ns:days>10</ns:days>" +
            "<ns:hours>5</ns:hours>" +
            "</ns:period>" +
            "</ns:changingTerm>" +
            "<ns:changingTerm>" +
            "<ns:date>2019-06-07</ns:date>" +
            "<ns:enforcer>Органы</ns:enforcer>" +
            "<ns:period>" +
            "<ns:years>3</ns:years>" +
            "<ns:months>6</ns:months>" +
            "<ns:days>11</ns:days>" +
            "<ns:hours>4</ns:hours>" +
            "</ns:period>" +
            "</ns:changingTerm>" +
            "<ns:release>" +
            "<ns:date>2020-09-08</ns:date>" +
            "<ns:cause>Причина</ns:cause>" +
            "</ns:release>" +
            "<ns:removeConvictionReasons>Основания</ns:removeConvictionReasons>" +
            "<ns:additionalInfo>Дополнительные данные</ns:additionalInfo>" +
            "</ns:conviction>" +
            "<ns:impeachment>" +
            "<ns:personalInfo>" +
            "<ns:mainData>" +
            "<ns:lastName>Ванчугов</ns:lastName>" +
            "<ns:firstName>Владимир</ns:firstName>" +
            "<ns:patronymicName>Иванович</ns:patronymicName>" +
            "<ns:birthDate>" +
            "<ns:year>1960</ns:year><ns:month>4</ns:month><ns:day>4</ns:day>" +
            "</ns:birthDate>" +
            "<ns:birthplace>Твой дом - тюрьма!</ns:birthplace>" +
            "</ns:mainData>" +
            "<ns:infoCenter>" +
            "<ns:code>031</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:infoCenter>" +
            "</ns:personalInfo>" +
            "<ns:impeachmentInfo>" +
            "<ns:date>2020-09-08</ns:date>" +
            "<ns:enforcer>Орган</ns:enforcer>" +
            "<ns:cause>" +
            "<ns:code>" +
            "<ns:code>123</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:code>" +
            "<ns:article>22</ns:article>" +
            "<ns:part>1</ns:part>" +
            "<ns:paragraph>3</ns:paragraph>" +
            "</ns:cause>" +
            "</ns:impeachmentInfo>" +
            "<ns:judgment>" +
            "<ns:description>Описывание</ns:description>" +
            "<ns:legalInfo>" +
            "<ns:date>2020-09-08</ns:date>" +
            "<ns:enforcer>Орган</ns:enforcer>" +
            "<ns:cause>" +
            "<ns:code>" +
            "<ns:code>123</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:code>" +
            "<ns:article>22</ns:article>" +
            "<ns:part>1</ns:part>" +
            "<ns:paragraph>3</ns:paragraph>" +
            "</ns:cause>" +
            "</ns:legalInfo>" +
            "</ns:judgment>" +
            "<ns:additionalInfo>Инфа</ns:additionalInfo>" +
            "</ns:impeachment>" +
            "<ns:manhunt>" +
            "<ns:personalInfo>" +
            "<ns:mainData>" +
            "<ns:lastName>Ванчугов</ns:lastName>" +
            "<ns:firstName>Владимир</ns:firstName>" +
            "<ns:patronymicName>Иванович</ns:patronymicName>" +
            "<ns:birthDate>" +
            "<ns:year>1960</ns:year><ns:month>4</ns:month><ns:day>4</ns:day>" +
            "</ns:birthDate>" +
            "<ns:birthplace>Твой дом - тюрьма!</ns:birthplace>" +
            "</ns:mainData>" +
            "<ns:infoCenter>" +
            "<ns:code>031</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:infoCenter>" +
            "</ns:personalInfo>" +
            "<ns:manhuntInfo>" +
            "<ns:date>2020-09-08</ns:date>" +
            "<ns:enforcer>Орган</ns:enforcer>" +
            "<ns:cause>" +
            "<ns:code>" +
            "<ns:code>123</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:code>" +
            "<ns:article>22</ns:article>" +
            "<ns:part>1</ns:part>" +
            "<ns:paragraph>3</ns:paragraph>" +
            "</ns:cause>" +
            "</ns:manhuntInfo>" +
            "<ns:additionalInfo>Инфа</ns:additionalInfo>" +
            "</ns:manhunt>" +
            "<ns:exemptionMaterial>" +
            "<ns:personalInfo>" +
            "<ns:mainData>" +
            "<ns:lastName>Ванчугов</ns:lastName>" +
            "<ns:firstName>Владимир</ns:firstName>" +
            "<ns:patronymicName>Иванович</ns:patronymicName>" +
            "<ns:birthDate>" +
            "<ns:year>1960</ns:year><ns:month>4</ns:month><ns:day>4</ns:day>" +
            "</ns:birthDate>" +
            "<ns:birthplace>Твой дом - тюрьма!</ns:birthplace>" +
            "</ns:mainData>" +
            "<ns:infoCenter>" +
            "<ns:code>031</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:infoCenter>" +
            "</ns:personalInfo>" +
            "<ns:denial>" +
            "<ns:date>2020-09-08</ns:date>" +
            "<ns:enforcer>Орган</ns:enforcer>" +
            "<ns:cause>" +
            "<ns:code>" +
            "<ns:code>123</ns:code>" +
            "<ns:value>Что-то там</ns:value>" +
            "</ns:code>" +
            "<ns:article>22</ns:article>" +
            "<ns:part>1</ns:part>" +
            "<ns:paragraph>3</ns:paragraph>" +
            "</ns:cause>" +
            "</ns:denial>" +
            "<ns:reason>" +
            "<ns:description>Описывание</ns:description>" +
            "<ns:cause>" +
            "<ns:code>" +
            "<ns:code>1234444</ns:code>" +
            "<ns:value>Что-то там ещё</ns:value>" +
            "</ns:code>" +
            "<ns:article>223</ns:article>" +
            "<ns:part>122</ns:part>" +
            "<ns:paragraph>344</ns:paragraph>" +
            "</ns:cause>" +
            "</ns:reason>" +
            "</ns:exemptionMaterial>" +
            "<ns:additionalInfo>Инфа</ns:additionalInfo>" +
            "</ns:records>\n" +
             "\t\t\t\t\t\t\t</ns:response>\n" +*/

    /*SmevResult testConnect(String xmlInput) {
        try {

            byte[] b = xmlInput.getBytes();

            String wsEndPoint = properties.getResponseUrl();
            URL url = new URL(wsEndPoint);
            URLConnection connection = url.openConnection();
            HttpURLConnection httpConn = (HttpURLConnection) connection;
            httpConn.setRequestMethod("POST");
            httpConn.setDoOutput(true);
            httpConn.setDoInput(true);
            httpConn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");

            OutputStream out = httpConn.getOutputStream();

            out.write(timeBasedUuid.getBytes(StandardCharsets.UTF_8));
            out.flush();

            httpConn.connect();
            Integer respCode = httpConn.getResponseCode();

            LOGGER.info(respCode.toString());

            SmevResult sr = new SmevResult();

            if (httpConn.getErrorStream() == null) {
                LOGGER.info("Error NULL");

                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;
                while ((length = httpConn.getInputStream().read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                sr.setSuccess(true);
                sr.setXml(result.toString("UTF-8"));
            } else {
                LOGGER.info("Error NOT NULL");

                ByteArrayOutputStream result = new ByteArrayOutputStream();
                byte[] buffer = new byte[1024];
                int length;
                while ((length = httpConn.getErrorStream().read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                sr.setSuccess(false);
                sr.setXml(result.toString("UTF-8"));
            }

            httpConn.disconnect();

            return sr;

        } catch (Exception e) {

            LOGGER.error("", e);

            throw new RuntimeException(e.getMessage(), e);
        }
    }*/

/*
    boolean isXmlContainsAttrByTag(String xml, String tag, String attrName) {

        class MyHandler extends DefaultHandler {

            private boolean b = false;

            public boolean isTagPresented() {
                return b;
            }

            @Override
            public void startElement(String uri, String lName, String qName, Attributes attr) throws SAXException {
                String tagName = qName;
                if(qName.contains(":")) {
                    int index = qName.lastIndexOf(":");
                    tagName = qName.substring(index + 1);
                }
                if (tagName.equals(tag)) {
                    for(int i = 0; i < attr.getLength(); i++) {
                        if(attr.getQName(i).contains(attrName) )
                        {
                            b = true;
                            break;
                        }
                    }
                }
            }
        }

        MyHandler handler = new MyHandler();

        try {
            InputStream stream = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
            SAXParserFactory factory = SAXParserFactory.newInstance();
            SAXParser saxParser = factory.newSAXParser();
            saxParser.parse(stream, handler);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }

        return handler.isTagPresented();
    }*/

}

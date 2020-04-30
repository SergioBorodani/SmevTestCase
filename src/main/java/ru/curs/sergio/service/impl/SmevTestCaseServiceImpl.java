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

            String mesId = parseMessageId(sr.getXml());

            String ackRequest = ackRequest(mesId);

            String ackUuid = UUID.randomUUID().toString();

            String ackHash = pathGenerator(ackUuid, true);

            SmevServiceMessageCursor smevServiceMessageCursor = new SmevServiceMessageCursor(callContext);

            try {
                String ackRequestFileName = ackHash + "/" + "Ack_" + ackUuid + "_Request.xml";
                PrintWriter printWriter = new PrintWriter(properties.getXmlServiceDir() + "/" + ackRequestFileName);
                printWriter.print(ackRequest);
                printWriter.flush();
                printWriter.close();

                smevServiceMessageCursor.setXml_file_request(ackRequestFileName);

            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }

            smevServiceMessageCursor.setOriginal_message_id(mesId);

            LOGGER.info(ackRequest);

            Date ackInitialDate = new Date();

            smevServiceMessageCursor.setInitial_message_time_stamp(ackInitialDate);

            sr = connect(ackRequest);

            Date ackLastUpdateDate = new Date();

            smevServiceMessageCursor.setLast_update_time_stamp(ackLastUpdateDate);

            try {
                String ackResponseFileName = ackHash + "/" + "Ack_" + ackUuid + "_Response.xml";
                PrintWriter printWriter = new PrintWriter(properties.getXmlServiceDir() + "/" + ackResponseFileName);
                printWriter.print(sr.getXml());
                printWriter.flush();
                printWriter.close();

                smevServiceMessageCursor.setXml_file_response(ackResponseFileName);

            } catch (Exception e) {
                throw new RuntimeException(e.getMessage(), e);
            }

            smevServiceMessageCursor.setSmev_status(SmevStatus.SUCCESS);

            smevServiceMessageCursor.tryInsert();

            LOGGER.info(sr.getXml());

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
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>MIIHsTCCB16gAwIBAgIQUcu4ABqr9a5B3D/MBeQkIDAKBggqhQMHAQEDAjCCAT8xGDAWBgUqhQNkARINMTAyNzcwMDE5ODc2NzEaMBgGCCqFAwOBAwEBEgwwMDc3MDcwNDkzODgxCzAJBgNVBAYTAlJVMSkwJwYDVQQIDCA3OCDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQszEmMCQGA1UEBwwd0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxWDBWBgNVBAkMTzE5MTAwMiwg0LMuINCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzLCDRg9C7LiDQlNC+0YHRgtC+0LXQstGB0LrQvtCz0L4g0LQuMTUxJjAkBgNVBAoMHdCf0JDQniAi0KDQvtGB0YLQtdC70LXQutC+0LwiMSUwIwYDVQQDDBzQotC10YHRgtC+0LLRi9C5INCj0KYg0KDQotCaMB4XDTE5MTIwNTExMDI0OVoXDTIwMTIwNTExMTI0OVowggFPMRowGAYJKoZIhvcNAQkCDAvQotCh0JzQrdCSMzErMCkGCSqGSIb3DQEJARYcVGF0eWFuYS5ub3ZpY2hrb3ZhQHJ0bGFicy5ydTEaMBgGCCqFAwOBAwEBEgwwMDUwNDcwNTM5MjAxGDAWBgUqhQNkARINMTAzNTAwOTU2NzQ1MDEdMBsGA1UECgwU0JDQniAi0KDQoiDQm9Cw0LHRgSIxOzA5BgNVBAkMMtGD0LsuINCf0YDQvtC70LXRgtCw0YDRgdC60LDRjywg0LQuIDIzLCDQutC+0LwgMTAxMRMwEQYDVQQHDArQpdC40LzQutC4MTEwLwYDVQQIDCg1MCDQnNC+0YHQutCy0L7QstGB0LrQsNGPINC+0LHQu9Cw0YHRgtGMMQswCQYDVQQGEwJSVTEdMBsGA1UEAwwU0JDQniAi0KDQoiDQm9Cw0LHRgSIwZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAzmdzBZBPXh3R2CyEBTSF7eN55XLb3bijAbiflGnLemxhIuawVEmAFGv3iNjWcV5nrgHbqFHdyfDOvuKpq9oZ2qOCBBkwggQVMA4GA1UdDwEB/wQEAwIE8DAdBgNVHQ4EFgQUiW5TocF4/TNB0JcX9VRSI4N0BgIwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMFMGCCsGAQUFBwEBBEcwRTBDBggrBgEFBQcwAoY3aHR0cDovL2NlcnRlbnJvbGwudGVzdC5nb3N1c2x1Z2kucnUvY2RwL3Rlc3RfY2FfcnRrLmNlcjAdBgNVHSAEFjAUMAgGBiqFA2RxATAIBgYqhQNkcQIwKwYDVR0QBCQwIoAPMjAxOTEyMDUxMTAyNDlagQ8yMDIwMTIwNTExMDI0OVowggEQBgUqhQNkcASCAQUwggEBDBrQmtGA0LjQv9GC0L7Qn9GA0L4gQ1NQIDQuMAwd0JrRgNC40L/RgtC+0J/RgNC+INCj0KYgdi4yLjAMYdCh0LXRgNGC0LjRhNC40LrQsNGC0Ysg0YHQvtC+0YLQstC10YLRgdGC0LLQuNGPINCk0KHQkSDQoNC+0YHRgdC40Lgg0KHQpC8xMjQtMzM4MCDQvtGCIDExLjA1LjIwMTgMYdCh0LXRgNGC0LjRhNC40LrQsNGC0Ysg0YHQvtC+0YLQstC10YLRgdGC0LLQuNGPINCk0KHQkSDQoNC+0YHRgdC40Lgg0KHQpC8xMjgtMjk4MyDQvtGCIDE4LjExLjIwMTYwJQYFKoUDZG8EHAwa0JrRgNC40L/RgtC+0J/RgNC+IENTUCA0LjAwZQYDVR0fBF4wXDBaoFigVoZUaHR0cDovL2NlcnRlbnJvbGwudGVzdC5nb3N1c2x1Z2kucnUvY2RwLzQ4MTBhZjBmNWRkYzk5MjQ3NmY3YmYwZGRhNGI3ZDBkZDk0Y2UxZjcuY3JsMIIBgAYDVR0jBIIBdzCCAXOAFEgQrw9d3Jkkdve/DdpLfQ3ZTOH3oYIBR6SCAUMwggE/MRgwFgYFKoUDZAESDTEwMjc3MDAxOTg3NjcxGjAYBggqhQMDgQMBARIMMDA3NzA3MDQ5Mzg4MQswCQYDVQQGEwJSVTEpMCcGA1UECAwgNzgg0KHQsNC90LrRgi3Qn9C10YLQtdGA0LHRg9GA0LMxJjAkBgNVBAcMHdCh0LDQvdC60YIt0J/QtdGC0LXRgNCx0YPRgNCzMVgwVgYDVQQJDE8xOTEwMDIsINCzLiDQodCw0L3QutGCLdCf0LXRgtC10YDQsdGD0YDQsywg0YPQuy4g0JTQvtGB0YLQvtC10LLRgdC60L7Qs9C+INC0LjE1MSYwJAYDVQQKDB3Qn9CQ0J4gItCg0L7RgdGC0LXQu9C10LrQvtC8IjElMCMGA1UEAwwc0KLQtdGB0YLQvtCy0YvQuSDQo9CmINCg0KLQmoIQcgsBVlAAELPoEaRoS+uv+zAKBggqhQMHAQEDAgNBAGc0p8UJzwTAocj8TuBILo1qDk5u90SjKbjVA4psdoRfwxi21la+FXi+qIgOuthV61qNQbFw2TcTcrtxJvRa8BQ=</ds:X509Certificate>\n" +
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
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
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
                "\t\t\t\t\t\t\t\t<ds:X509Certificate>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</ds:X509Certificate>\n" +
                "\t\t\t\t\t\t\t</ds:X509Data>\n" +
                "\t\t\t\t\t\t</ds:KeyInfo>\n" +
                "\t\t\t\t\t</ds:Signature>\n" +
                "\t\t\t\t</ns2:SMEVSignature>\n" +
                "\t\t\t</ns2:ResponseMessage>\n" +
                "\t\t</ns2:GetResponseResponse>\n" +
                "\t</soap:Body>\n" +
                "</soap:Envelope>";*/

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
                "\t\t\t\t\t\t\t<ns4:response\n" +
                "\t\t\t\t\t\t\t\txmlns:ns4=\"urn://ru/mvd/ibd-m/convictions/search/1.0.2\" Id=\"Id1\">\n" +
                "\t\t\t\t\t\t\t\t<ns4:noRecords/>\n" +
                "\t\t\t\t\t\t\t</ns4:response>\n" +
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
                "<ns1:ZadorgResponse " +
                "xmlns:ns1=\"urn://x-artefacts-fns-zadorg/root/548-04/4.0.4\" " +
                "ИдЗапрос=\"951c9bb05eb94a4da0dd961f69466b16\">" +
                "<ns1:КодОбраб>11</ns1:КодОбраб>" +
                "</ns1:ZadorgResponse>" +
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
                //"\t\t\t\t\t\t<MessagePrimaryContent>\n" +
                "<ns2:RequestRejected>" +
                "<ns2:RejectionReasonCode>NO_DATA</ns2:RejectionReasonCode>" +
                "<ns2:RejectionReasonDescription>KVS03203 Нет данных</ns2:RejectionReasonDescription>" +
                "</ns2:RequestRejected>" +
                //"\t\t\t\t\t\t</MessagePrimaryContent>\n" +
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

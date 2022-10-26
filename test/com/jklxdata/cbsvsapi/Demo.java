package com.jklxdata.cbsvsapi;
import com.jklxdata.cbsvsapi.SVSBusiness;
import com.jklxdata.cbsvsapi.SVSBusinessFactory;
import com.jklxdata.cbsvsapi.common.exception.ServiceException;

import java.io.*;
import java.util.Arrays;

public class Demo {

    private SVSBusiness svsBusiness;
    private BufferedReader scanner;

    public Demo() throws IOException {
    	this.scanner = new BufferedReader(new InputStreamReader(System.in));
    	
    	//TODO 提示输入IP和端口号，使用输入得IP和端口号获取运算实例
    	System.out.println("请手动输入服务IP");
    	String ip=scanner.readLine();
    	System.out.println("请手动输入端口号");
    	String port=scanner.readLine();
        this.svsBusiness = SVSBusinessFactory.getSVSBusinessImpl(ip, port);
    }

    public void doMain() {
        try {
            while (true) {
                System.out.println("******************************************************************************");
                System.out.println("输入数字选择功能：");
                System.out.println("1、导出证书");
                System.out.println("2、解析证书信息");
                System.out.println("3、验证证书");
                System.out.println("4、RSA PKCS#1 数据签名");
                System.out.println("5、RSA PKCS#1 数据验签 ");
                System.out.println("6、RSA PKCS#7 非分离式消息签名 ");
                System.out.println("7、RSA PKCS#7 非分离式消息验签 ");
                System.out.println("8、RSA PKCS#7 分离式消息签名");
                System.out.println("9、RSA PKCS#7 分离式消息验签");
                System.out.println("10、RSA PKCS#1 大文件签名");
                System.out.println("11、RSA PKCS#1 大文件验签");
                System.out.println("12、RSA PKCS#7 分离式大文件签名");
                System.out.println("13、RSA PKCS#7 分离式大文件验签");
                System.out.println("------------------------------                                                                         ");
                System.out.println("14、SM2 PKCS#1 数据签名");
                System.out.println("15、SM2 PKCS#1 数据验签");
                System.out.println("16、SM2 PKCS#7 非分离式消息签名 ");
                System.out.println("17、SM2 PKCS#7 非分离式消息验签");
                System.out.println("18、SM2 PKCS#7 分离式消息签名");
                System.out.println("19、SM2 PKCS#7 分离式消息验签");
                System.out.println("20、SM2 PKCS#1 大文件签名");
                System.out.println("21、SM2 PKCS#1 大文件验签");
                System.out.println("22、SM2 PKCS#7 分离式大文件签名");
                System.out.println("23、SM2 PKCS#7 分离式大文件验签");
                System.out.println("------------------------------                                                                         ");
                System.out.println("24、消息加密");
                System.out.println("25、消息解密");
                System.out.println("请输入数字选择功能！");

                switch (Integer.parseInt(scanner.readLine())) {
                    case 1:
                        exportCert();
                        break;
                    case 2:
                        parseCert();
                        break;
                    case 3:
                        validateCert();
                        break;
                    case 4:
                        rsaP1Sign();
                        break;
                    case 5:
                        p1VerifySignedDataWithCertandSN("RSA");
                        break;
                    case 6:
                        rsaP7Sign();
                        break;
                    case 7:
                        p7VerifySignedMessage();
                        break;
                    case 8:
                        rsaP7SignDetach();
                        break;
                    case 9:
                        p7VerifySignedMessageDetach();
                        break;
                    case 10:
                        rsaP1SignDataInit();
                        break;
                    case 11:
                        rsaP1SignVerify();
                        break;
                    case 12:
                        rsaP7SignMessageInit();
                        break;
                    case 13:
                        rsaP7VerifySignedMessageInit();
                        break;
                    case 14:
                        sm2P1Sign();
                        break;
                    case 15:
                        p1VerifySignedDataWithCertandSN("SM2");
                        break;
                    case 16:
                        sm2P7Sign();
                        break;
                    case 17:
                        p7VerifySignedMessage();
                        break;
                    case 18:
                        sm2P7SignDetach();
                        break;
                    case 19:
                        p7VerifySignedMessageDetach();
                        break;
                    case 20:
                        sm2P1SignDataInit();
                        break;
                    case 21:
                        sm2P1SignVerify();
                        break;
                    case 22:
                        sm2P7SignMessageInit();
                        break;
                    case 23:
                        sm2P7VerifySignedMessageInit();
                        break;
                    case 24:
                        envelopMsg();
                        break;
                    case 25:
                        openEnvelopMsg();
                        break;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("输入可能有误，请检查并重新输入！");
        }
    }

    public static void main(String[] args) throws ServiceException, IOException {
        new Demo().doMain();
    }

    private void rsaP1SignDataInit() throws IOException, ServiceException {
        int hashAlg = hashAlg("RSA");
        int keyIndex = keyIndex();
        String authcode = authcode();
        System.out.println("正在签名");
        String filePath = filePase();
        BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(filePath));
        byte[] signature_tmp = new byte[1024];
        int len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length);
        String signature_init = svsBusiness.rsaP1SignDataInit(hashAlg, Arrays.copyOfRange(signature_tmp, 0, len));
        if (len < 1024) {
        	//如果len小于1024，表示文件大小 小于1024字节，不需要update
            bufferedInputStream.close();
            String signature = svsBusiness.rsaP1SignDataFinal(hashAlg, signature_init, keyIndex, authcode);
            System.out.println(signature);
            System.out.println("签名成功");
        } else {
            while ((len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length)) != -1) {
                if (len != signature_tmp.length) {
                	signature_init = svsBusiness.rsaP1SignDataUpdate(hashAlg, signature_init, Arrays.copyOfRange(signature_tmp, 0, len));
                    break;
                }
                signature_init = svsBusiness.rsaP1SignDataUpdate(hashAlg, signature_init, signature_tmp);
            }
            bufferedInputStream.close();
            String signature = svsBusiness.rsaP1SignDataFinal(hashAlg, signature_init, keyIndex, authcode);
            System.out.println(signature);
            System.out.println("签名成功");
        }
    }

    private String filePase() throws IOException {
        System.out.println("请输入文件的绝对路径");
        return scanner.readLine();
    }

    private String certDN() throws IOException {
        System.out.println("请输入DN，例：CN=baidu.com");
        return scanner.readLine();
    }

    private void envelopMsg() throws ServiceException, IOException {
        String certDN = certDN();
        byte[] source = source();
        System.out.println("消息加密");
        String tmp = svsBusiness.envelopMsg(certDN, source);
        System.out.println("加密成功");
        System.out.println(tmp);
    }

    private void openEnvelopMsg() throws ServiceException, IOException {
        System.out.println("消息解密");
        String opMsg = opMsg();
        svsBusiness.openEnvelopMsg(opMsg);
        System.out.println("解密成功");
    }

    private String opMsg() throws IOException {
        System.out.println("请输入密文");
        return scanner.readLine();
    }

    private void sm2P1SignDataInit() throws IOException, ServiceException {
        String certBase64 = certBase64();
        int hashAlg = hashAlg("SM2");
        int keyIndex = keyIndex();
        String authcode = authcode();
        System.out.println("正在签名");
        String filePath = filePase();
        BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(filePath));
        byte[] signature_tmp = new byte[1024];
        String signature_init = null;

        int len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length);
        signature_init = svsBusiness.sm2P1SignDataInit(certBase64, Arrays.copyOfRange(signature_tmp, 0, len));
        if (len < 1024) {
            bufferedInputStream.close();
            String signature = svsBusiness.rsaP1SignDataFinal(hashAlg, signature_init, keyIndex, authcode);
            System.out.println(signature);
            System.out.println("签名成功");
        } else {
            while ((len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length)) != -1) {
                if (len != signature_tmp.length) {
                	signature_init = svsBusiness.rsaP1SignDataUpdate(hashAlg, signature_init, Arrays.copyOfRange(signature_tmp, 0, len));
                    break;
                }
                signature_init = svsBusiness.rsaP1SignDataUpdate(hashAlg, signature_init, signature_tmp);
            }
            bufferedInputStream.close();
            String signature = svsBusiness.rsaP1SignDataFinal(hashAlg, signature_init, keyIndex, authcode);
            System.out.println(signature);
            System.out.println("签名成功");
        }
    }

    private void rsaP1SignVerify() throws ServiceException, IOException {
        System.out.println("请输入使用什么来进行验签：1.公钥base64编码 2.证书序列号");

        switch (Integer.parseInt(scanner.readLine())) {
            case 1:
                int hashAlg = hashAlg("RSA");

                int verifyLevel = verifyLevel();

                String signature = signature();
                String certBase64 = certBase64();

                String filePath = filePase();
                BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(filePath));
                byte[] signature_tmp = new byte[1024];
                String verify_init = null;
                int len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length);
                verify_init = svsBusiness.rsaP1VerifySignedDataInit(hashAlg, Arrays.copyOfRange(signature_tmp, 0, len));
                if (len < 1024) {
                    bufferedInputStream.close();
                    System.out.println("正在执行验签（客户端证书）");
                    svsBusiness.rsaP1VerifySignedDataFinalWithCert(verify_init, hashAlg, certBase64, signature, verifyLevel);
                    System.out.println("验签成功（客户端证书）");
                } else {
                    while ((len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length)) != -1) {
                        if (len != signature_tmp.length) {
                        	verify_init = svsBusiness.rsaP1VerifySignedDataUpdate(hashAlg, verify_init, Arrays.copyOfRange(signature_tmp, 0, len));
                            break;
                        }
                        verify_init = svsBusiness.rsaP1VerifySignedDataUpdate(hashAlg, verify_init, signature_tmp);
                    }
                    bufferedInputStream.close();
                    System.out.println("正在执行验签（客户端证书）");
                    svsBusiness.rsaP1VerifySignedDataFinalWithCert(verify_init, hashAlg, certBase64, signature, verifyLevel);
                    System.out.println("验签成功（客户端证书）");
                }
                break;
            case 2:
                int hashAlgSN = hashAlg("RSA");

                int verifyLevelSN = verifyLevel();

                String signatureSN = signature();
                String certBase64SN = certSN();

                String filePathSN = filePase();
                BufferedInputStream bufferedInputStreamSN = new BufferedInputStream(new FileInputStream(filePathSN));

                byte[] signature_tmpSN = new byte[1024];
                String verify_initSN = null;
                int lenSN = bufferedInputStreamSN.read(signature_tmpSN, 0, signature_tmpSN.length);
                verify_initSN = svsBusiness.rsaP1VerifySignedDataInit(hashAlgSN, Arrays.copyOfRange(signature_tmpSN, 0, lenSN));
                if (lenSN < 1024) {
                    bufferedInputStreamSN.close();
                    System.out.println("正在执行验签（SN）");
                    svsBusiness.rsaP1VerifySignedDataFinalWithCertSN(verify_initSN, hashAlgSN, certBase64SN, signatureSN, verifyLevelSN);
                    System.out.println("验签成功（SN）");
                } else {
                    while ((lenSN = bufferedInputStreamSN.read(signature_tmpSN, 0, signature_tmpSN.length)) != -1) {
                        if (lenSN != signature_tmpSN.length) {
                        	verify_initSN = svsBusiness.rsaP1VerifySignedDataUpdate(hashAlgSN, verify_initSN, Arrays.copyOfRange(signature_tmpSN, 0, lenSN));
                            break;
                        }
                        verify_initSN = svsBusiness.rsaP1VerifySignedDataUpdate(hashAlgSN, verify_initSN, signature_tmpSN);
                    }
                    bufferedInputStreamSN.close();
                    System.out.println("正在执行验签（SN）");
                    svsBusiness.rsaP1VerifySignedDataFinalWithCertSN(verify_initSN, hashAlgSN, certBase64SN, signatureSN, verifyLevelSN);
                    System.out.println("验签成功（SN）");
                }
                break;
        }
    }

    private void sm2P1SignVerify() throws ServiceException, IOException {
        System.out.println("请输入要验证的方式 1.证书验证 2.序列号验证");
        switch (Integer.parseInt(scanner.readLine())) {
            case 1:
                int verifyLevel = verifyLevel();
                String signature = signature();
                String certBase64 = certBase64();
                String filePath = filePase();
                BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(filePath));
                byte[] Verify_tmp = new byte[1024];
                String verify_init = null;
                int len = bufferedInputStream.read(Verify_tmp, 0, Verify_tmp.length);
                verify_init = svsBusiness.sm2P1VerifySignedDataInit(certBase64, Arrays.copyOfRange(Verify_tmp, 0, len));
                if (len < 1024) {
                    bufferedInputStream.close();
                    System.out.println("正在执行验签（客户端证书）");
                    svsBusiness.sm2P1VerifySignedDataFinalWithCert(verify_init, certBase64, signature, verifyLevel);
                    System.out.println("验签成功（客户端证书）");
                } else {
                    while ((len = bufferedInputStream.read(Verify_tmp, 0, Verify_tmp.length)) != -1) {
                        if (len != Verify_tmp.length) {
                        	verify_init = svsBusiness.sm2P1VerifySignedDataUpdate(verify_init, Arrays.copyOfRange(Verify_tmp, 0, len));
                            break;
                        }
                        verify_init = svsBusiness.sm2P1VerifySignedDataUpdate(verify_init, Verify_tmp);
                    }
                    bufferedInputStream.close();
                    System.out.println("正在执行验签（客户端证书）");
                    svsBusiness.sm2P1VerifySignedDataFinalWithCert(verify_init, certBase64, signature, verifyLevel);
                    System.out.println("验签成功（客户端证书）");
                }
                break;
            case 2:
                int verifyLevelSN = verifyLevel();
                String signatureSN = signature();
                String certSN = certSN();
                String certBase64SN = certBase64();
                String filePathSN = filePase();
                BufferedInputStream bufferedInputStreamSN = new BufferedInputStream(new FileInputStream(filePathSN));
                byte[] Verify_tmpSN = new byte[1024];
                String verify_initSN = null;
                int lenSN = bufferedInputStreamSN.read(Verify_tmpSN, 0, Verify_tmpSN.length);
                verify_initSN = svsBusiness.sm2P1VerifySignedDataInit(certBase64SN, Arrays.copyOfRange(Verify_tmpSN, 0, lenSN));
                if (lenSN < 1024) {
                    bufferedInputStreamSN.close();
                    System.out.println("正在执行验签（序列号）");
                    svsBusiness.sm2P1VerifySignedDataFinalWithCertSN(verify_initSN, certSN, signatureSN, verifyLevelSN);
                    System.out.println("验签成功（SN）");
                } else {
                    while ((lenSN = bufferedInputStreamSN.read(Verify_tmpSN, 0, Verify_tmpSN.length)) != -1) {
                        if (lenSN != Verify_tmpSN.length) {
                            String verify_updateSN = svsBusiness.sm2P1VerifySignedDataUpdate(verify_initSN, Arrays.copyOfRange(Verify_tmpSN, 0, lenSN));
                            verify_initSN = verify_updateSN;
                        }
                        String verify_updateSN = svsBusiness.sm2P1VerifySignedDataUpdate(verify_initSN, Verify_tmpSN);
                        verify_initSN = verify_updateSN;
                    }
                    bufferedInputStreamSN.close();
                    System.out.println("正在执行验签（序列号）");
                    svsBusiness.sm2P1VerifySignedDataFinalWithCertSN(verify_initSN, certSN, signatureSN, verifyLevelSN);
                    System.out.println("验签成功（SN）");
                }
                break;
        }
    }
    
    private void rsaP7SignMessageInit() throws ServiceException, IOException {
        int hashAlg = hashAlg("RSA");
        int keyIndex = keyIndex();
        String authcode = authcode();
        System.out.println("正在签名");
        String filePath = filePase();
        BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(filePath));
        byte[] signature_tmp = new byte[1024];
        int len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length);
        String signature_init = null;
        signature_init = svsBusiness.rsaP7SignMessageInit(hashAlg, Arrays.copyOfRange(signature_tmp, 0, len));
        if (len < 1024) {
            bufferedInputStream.close();
            String signature = svsBusiness.rsaP7SignMessageFinal(hashAlg, signature_init, keyIndex, authcode);
            System.out.println(signature);
            System.out.println("签名成功");
        } else {
            while ((len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length)) != -1) {
                if (len != signature_tmp.length) {
                	signature_init = svsBusiness.rsaP7SignMessageUpdate(hashAlg, signature_init, Arrays.copyOfRange(signature_tmp, 0, len));
                    break;
                }
                signature_init = svsBusiness.rsaP7SignMessageUpdate(hashAlg, signature_init, signature_tmp);
            }
            bufferedInputStream.close();
            String signature = svsBusiness.rsaP7SignMessageFinal(hashAlg, signature_init, keyIndex, authcode);
            System.out.println(signature);
            System.out.println("签名成功");
        }
    }

    private void sm2P7SignMessageInit() throws ServiceException, IOException {
        int keyIndex = keyIndex();
        String authcode = authcode();
        System.out.println("正在签名");
        String certBase64 = certBase64();
        String filePath = filePase();
        BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(filePath));
        byte[] signature_tmp = new byte[1024];
        String signature_init = null;
        int len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length);
        signature_init = svsBusiness.sm2P7SignMessageInit(certBase64, Arrays.copyOfRange(signature_tmp, 0, len));

        if (len < 1024) {
            bufferedInputStream.close();
            String signature = svsBusiness.sm2P7SignMessageFinal(signature_init, keyIndex, authcode);
            System.out.println(signature);
            System.out.println("签名成功");
        } else {
            while ((len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length)) != -1) {
                if (len != signature_tmp.length) {
                	signature_init = svsBusiness.sm2P7SignMessageUpdate(signature_init, Arrays.copyOfRange(signature_tmp, 0, len));
                    break;
                }
                signature_init = svsBusiness.sm2P7SignMessageUpdate(signature_init, signature_tmp);
            }
            bufferedInputStream.close();
            String signature = svsBusiness.sm2P7SignMessageFinal(signature_init, keyIndex, authcode);
            System.out.println(signature);
            System.out.println("签名成功");
        }
    }

    private void rsaP7VerifySignedMessageInit() throws ServiceException, IOException {

        int hashAlg = hashAlg("RSA");
        System.out.println("正在验签");
        String signature = signature();
        String filePath = filePase();
        BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(filePath));
        byte[] signature_tmp = new byte[1024];
        String verify_init = null;
        int len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length);
        verify_init = svsBusiness.rsaP7VerifySignedMessageInit(hashAlg, Arrays.copyOfRange(signature_tmp, 0, len));

        if (len < 1024) {
            bufferedInputStream.close();
            svsBusiness.rsaP7VerifySignedMessageFinal(verify_init, hashAlg, signature);
            System.out.println("验签成功");
        } else {
            while ((len = bufferedInputStream.read(signature_tmp, 0, signature_tmp.length)) != -1) {
                if (len != signature_tmp.length) {
                	verify_init = svsBusiness.rsaP7VerifySignedMessageUpdate(hashAlg, verify_init, Arrays.copyOfRange(signature_tmp, 0, len));
                    break;
                }
                verify_init = svsBusiness.rsaP7VerifySignedMessageUpdate(hashAlg, verify_init, signature_tmp);
            }
            bufferedInputStream.close();
            svsBusiness.rsaP7VerifySignedMessageFinal(verify_init, hashAlg, signature);
            System.out.println("验签成功");
        }
    }

    private void sm2P7VerifySignedMessageInit() throws ServiceException, IOException {
        hashAlg("SM2");
        System.out.println("正在验签");
        String signature = signature();
        String certBase64 = certBase64();
        String filePath = filePase();
        byte[] Verify_tmp = new byte[1024];

        BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(filePath));
        String verify_init = null;
        int len = bufferedInputStream.read(Verify_tmp, 0, Verify_tmp.length);
        verify_init = svsBusiness.sm2P7VerifySignedMessageInit(certBase64, Arrays.copyOfRange(Verify_tmp, 0, len));
        if (len < 1024) {
            bufferedInputStream.close();
            svsBusiness.sm2P7VerifySignedMessageFinal(verify_init, signature);
            System.out.println("验签成功");
        } else {
            while ((len = bufferedInputStream.read(Verify_tmp, 0, Verify_tmp.length)) != -1) {
                if (len != Verify_tmp.length) {
                	verify_init = svsBusiness.sm2P7VerifySignedMessageUpdate(verify_init, Arrays.copyOfRange(Verify_tmp, 0, len));
                    break;
                }
                verify_init = svsBusiness.sm2P7VerifySignedMessageUpdate(verify_init, Verify_tmp);
            }
            bufferedInputStream.close();
            svsBusiness.sm2P7VerifySignedMessageFinal(verify_init, signature);
            System.out.println("验签成功");
        }
    }

    private void exportCert() throws ServiceException, IOException {
        String certBase64 = svsBusiness.exportCert(identification());
        System.out.println(certBase64);
    }

    private String identification() throws IOException {
        System.out.println("请输入密钥标识");
        return scanner.readLine();
    }

    private void parseCert() throws ServiceException, IOException {
        String certBase64 = certBase64();
        System.out.println("证书版本：" + svsBusiness.parseCert(SVSBusiness.TYPE_VERSION, certBase64));
        System.out.println("证书序列号：" + svsBusiness.parseCert(SVSBusiness.VL_CRL, certBase64));
        System.out.println("证书颁发者信息" + svsBusiness.parseCert(SVSBusiness.TYPE_ISSUER, certBase64));
        System.out.println("证书有效期：" + svsBusiness.parseCert(SVSBusiness.TYPE_VALIDITY, certBase64));
        System.out.println("证书拥有者信息" + svsBusiness.parseCert(SVSBusiness.TYPE_SUBJECT, certBase64));
        System.out.println("证书公钥信息" + svsBusiness.parseCert(SVSBusiness.TYPE_PUBKEY, certBase64));
    }

    private void validateCert() throws ServiceException, IOException {
        String certBase64 = certBase64();
        if (((svsBusiness.validateCert(certBase64, true)) == 0)) {
            System.out.println("验证证书有效");
        }
    }

    private String certBase64() throws IOException {
        System.out.println("请输入证书Base64编码字符串");
        return scanner.readLine();
    }

    //rsa 单步签名
    private void rsaP1Sign() throws ServiceException, IOException {
        int keyIndex = keyIndex();
        String authcode = authcode();
        int hashAlg = hashAlg("RSA");
        byte[] source = source();
        String signature = svsBusiness.rsaP1Sign(keyIndex, authcode, hashAlg, source);
        System.out.println(signature);
    }

    private void sm2P1Sign() throws ServiceException, IOException {
        int keyIndex = keyIndex();
        String authcode = authcode();
        int hashAlg = hashAlg("SM2");
        byte[] source = source();
        String signature = svsBusiness.rsaP1Sign(keyIndex, authcode, hashAlg, source);
        System.out.println(signature);
    }

    private void p1VerifySignedDataWithCertandSN(String rsaorsm2) throws ServiceException, IOException {
        System.out.println("请选择验证方式：1.证书Base64编码   2.证书序列号验证");

        switch (Integer.parseInt(scanner.readLine())) {
            case 1:
                byte[] source = source();
                String certBase64 = certBase64();
                String signature = signature();
                int verifyLevel = verifyLevel();

                System.out.println("正在执行验签（客户端证书Baes64）");
                svsBusiness.p1VerifySignedDataWithCert(certBase64, source, signature, verifyLevel);
                System.out.println("验签成功（客户端证书Baes64）");
                break;
            case 2:
                byte[] sourceSN = source();
                String signatureSN = signature();
                int verifyLevelSN = verifyLevel();
                System.out.println("正在执行验签（证书序列号）");
                String certSN = certSN();
                svsBusiness.p1VerifySignedDataWithCertSN(certSN, sourceSN, signatureSN, verifyLevelSN);
                System.out.println("验签成功（证书序列号）");
                break;
        }
    }

    private void rsaP7Sign() throws ServiceException, IOException {
        int keyIndex = keyIndex();
        String authcode = authcode();
        int hashAlg = hashAlg("RSA");
        byte[] source = source();
        //非分离
        System.out.println("非分离签名开始");
        String signedMessage = svsBusiness.rsaP7Sign(keyIndex, authcode, hashAlg, source);
        System.out.println("非分离签名成功");
        System.out.println(signedMessage);
    }

    private void sm2P7Sign() throws ServiceException, IOException {
        int keyIndex = keyIndex();
        String authcode = authcode();
        hashAlg("SM2");
        byte[] source = source();
        //非分离
        System.out.println("非分离签名开始");
        String signedMessage = svsBusiness.sm2P7Sign(keyIndex, authcode, source);
        System.out.println("非分离签名成功");
        System.out.println(signedMessage);
    }

    private void p7VerifySignedMessage() throws ServiceException, IOException {
        String signedMessage = signature();
        System.out.println("非分离验签开始");
        svsBusiness.p7VerifySignedMessage(signedMessage);
        System.out.println("非分离验签成功");
    }

    private void rsaP7SignDetach() throws ServiceException, IOException {
        int keyIndex = keyIndex();
        String authcode = authcode();
        int hashAlg = hashAlg("RSA");
        byte[] source = source();
        System.out.println("分离签名开始");
        String separateSignedMessage = svsBusiness.rsaP7SignDetach(keyIndex, authcode, hashAlg, source);
        System.out.println(separateSignedMessage);
        System.out.println("分离签名成功");
    }

    private void sm2P7SignDetach() throws ServiceException, IOException {
        int keyIndex = keyIndex();
        String authcode = authcode();
        hashAlg("SM2");
        byte[] source = source();
        System.out.println("分离签名开始");
        String separateSignedMessage = svsBusiness.sm2P7SignDetach(keyIndex, authcode, source);
        System.out.println(separateSignedMessage);
        System.out.println("分离签名成功");
    }

    private void p7VerifySignedMessageDetach() throws ServiceException, IOException {
        byte[] source = source();
        String separateSignedMessage = signature();
        System.out.println("分离验签开始");
        svsBusiness.p7VerifySignedMessageDetach(source, separateSignedMessage);
        System.out.println("分离验签成功");
    }

    private String certSN() throws IOException {
        System.out.println("请输入证书序列号");
        return scanner.readLine();
    }

    private String signature() throws IOException {
        System.out.println("提示：签名值要与之对应");
        System.out.println("请输入签名值：");
        return scanner.readLine();
    }

    private int verifyLevel() throws IOException {
        System.out.println("请输入十进制整数，表示证书验证级别，0：验证时间；1：验 证时间和根证书签名；2：验证时间、根证书签名和 CRL。");
        return Integer.parseInt(scanner.readLine());
    }

    private int keyIndex() throws IOException {
        System.out.println("请输入密钥索引（十进制整数）");
        return Integer.parseInt(scanner.readLine());
    }

    private String authcode() throws IOException {
        System.out.println("请输入访问控制码");
        return scanner.readLine();
    }

    private int hashAlg(String RSAorSM2) throws IOException {
        if (RSAorSM2.equals("RSA")) {
            System.out.println("请输入数字选择要用的杂凑算法");
            System.out.println("1.HASH_SHA1");
            System.out.println("2.HASH_SHA256");
            switch (Integer.parseInt(scanner.readLine())) {
                case 1:
                    return SVSBusiness.HASH_SHA1;
                case 2:
                    return SVSBusiness.HASH_SHA256;
                case 3:
                    return SVSBusiness.HASH_SM3;
            }
        } else {
            System.out.println("SM2签名验签默认使用SM3");
            return SVSBusiness.HASH_SM3;
        }
        return 0;
    }

    private byte[] source() throws IOException {
        System.out.println("请输入数据原文！");
        String source_str = scanner.readLine();
        byte[] source_byte = source_str.getBytes();
        return source_byte;
    }

}

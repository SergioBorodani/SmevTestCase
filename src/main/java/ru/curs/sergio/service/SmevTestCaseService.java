package ru.curs.sergio.service;

import com.digt.trusted.xmlsig.Consts;
import ru.curs.celesta.CallContext;

public interface SmevTestCaseService {

    static final String digUri = Consts.URN_GOST_DIGEST_2012_256;
    static final String algUri = Consts.URN_GOST_SIGN_2012_256;

    void initialize();

    String getSnilsResponse(String uuid);

    String getMvdResponse(String uuid);

    String getZadolgResponse(String timeBasedUuid);

    String getRejectResponse(String timeBasedUuid);

    String getNalogResponse(String timeBasedUuid);

    void getFromSmev(CallContext callContext);

}

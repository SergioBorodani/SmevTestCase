package ru.curs.sergio.controller;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.curs.celesta.SystemCallContext;
import ru.curs.sergio.service.SmevTestCaseService;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;

@Controller
//@RestController
//@RequestMapping("/api")
public class SmevTestCaseController {

    private final SmevTestCaseService smevTestCaseService;

    public SmevTestCaseController(SmevTestCaseService smevTestCaseService) {
        this.smevTestCaseService = smevTestCaseService;
        this.smevTestCaseService.initialize();
    }

//    @PostMapping("/snils")
//    public String snilsResponse(@RequestBody @Valid @NotBlank String uuid) {
//        //String uid = new String(uuid, StandardCharsets.UTF_8);
//
//        System.out.println(uuid);
//
//        String resp = smevTestCaseService.getSnilsResponse(uuid);
//
//        System.out.println(resp);
//
//        return resp;
//    }
//
//    @PostMapping("/mvd")
//    public String getMvdResponse(@RequestBody @Valid @NotBlank String uuid) {
//
//        System.out.println(uuid);
//
//        String resp = smevTestCaseService.getMvdResponse(uuid);
//
//        System.out.println(resp);
//
//        return resp;
//    }
//
//    @PostMapping("/zadolg")
//    public String getZadolgResponse(@RequestBody @Valid @NotBlank String uuid) {
//
//        System.out.println(uuid);
//
//        String resp = smevTestCaseService.getZadolgResponse(uuid);
//
//        System.out.println(resp);
//
//        return resp;
//    }
//
//    @PostMapping("/reject")
//    public String getRejectResponse(@RequestBody @Valid @NotBlank String uuid) {
//
//        System.out.println(uuid);
//
//        String resp = smevTestCaseService.getRejectResponse(uuid);
//
//        System.out.println(resp);
//
//        return resp;
//    }
//
//    @PostMapping("/nalog")
//    public String getNalogResponse(@RequestBody @Valid @NotBlank String uuid) {
//
//        System.out.println(uuid);
//
//        String resp = smevTestCaseService.getNalogResponse(uuid);
//
//        System.out.println(resp);
//
//        return resp;
//    }

    @Scheduled(cron = "${cron.get.from.smev}")
    public void getDataFromSmev() {

        smevTestCaseService.getFromSmev(new SystemCallContext());
    }
}

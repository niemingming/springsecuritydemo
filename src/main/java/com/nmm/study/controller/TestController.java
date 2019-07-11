package com.nmm.study.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/book")
public class TestController {

    public TestController(){
        System.out.println(1111);
    }

    @GetMapping
    public String test(){
        return "success";
    }
}

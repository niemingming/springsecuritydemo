package com.nmm.study.test;

import java.util.regex.Pattern;

public class RegexTest {

    public static void main(String[] args) {
        Pattern BCRYPT_PATTERN = Pattern
                .compile("\\A\\$2a?\\$\\d\\d\\$[./0-9A-Za-z]{53}");

        System.out.println(BCRYPT_PATTERN.matcher("a1231D").matches());
    }
}

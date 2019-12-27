/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package HW4;

import java.util.Scanner;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;



/**
 *
 * @author Kishore Thamilvanan
 */
public class MyPatternValidator {

    /**
     * 1. Username checking class
     */
    public static class UsernameValidator {

        private Pattern pattern;
        private Matcher matcher;

        private static final String USERNAME_PATTERN = "^[a-z0-9_-]{3,15}$";

        public UsernameValidator() {
            pattern = Pattern.compile(USERNAME_PATTERN);
        }

        /**
         * Validate username with regular expression
         *
         * @param username username for validation
         * @return true valid username, false invalid username
         */
        public boolean validate(final String username) {

            matcher = pattern.matcher(username);
            return matcher.matches();

        }
    }

    /**
     * 2. Password checking class
     */
    public static class PasswordValidator {

        private Pattern pattern;
        private Matcher matcher;

        private static final String PASSWORD_PATTERN
                = "((?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%]).{6,20})";

        public PasswordValidator() {
            pattern = Pattern.compile(PASSWORD_PATTERN);
        }

        /**
         * Validate password with regular expression
         *
         * @param password password for validation
         * @return true valid password, false invalid password
         */
        public boolean validate(final String password) {

            matcher = pattern.matcher(password);
            return matcher.matches();

        }
    }

    /**
     * 3. Hex Color Code
     */
    public static class HexValidator {

        private Pattern pattern;
        private Matcher matcher;

        private static final String HEX_PATTERN = "^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$";

        public HexValidator() {
            pattern = Pattern.compile(HEX_PATTERN);
        }

        /**
         * Validate hex with regular expression
         *
         * @param hex hex for validation
         * @return true valid hex, false invalid hex
         */
        public boolean validate(final String hex) {

            matcher = pattern.matcher(hex);
            return matcher.matches();

        }
    }

    /**
     * 4. Email
     */
    public static class EmailValidator {

        private Pattern pattern;
        private Matcher matcher;

        private static final String EMAIL_PATTERN
                = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
                + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

        public EmailValidator() {
            pattern = Pattern.compile(EMAIL_PATTERN);
        }

        /**
         * Validate hex with regular expression
         *
         * @param hex hex for validation
         * @return true valid hex, false invalid hex
         */
        public boolean validate(final String hex) {

            matcher = pattern.matcher(hex);
            return matcher.matches();

        }
    }

    /**
     * 5. Image File Extension
     */
    public static class ImageValidator {

        private Pattern pattern;
        private Matcher matcher;

        private static final String IMAGE_PATTERN
                = "([^\\s]+(\\.(?i)(jpg|png|gif|bmp))$)";

        public ImageValidator() {
            pattern = Pattern.compile(IMAGE_PATTERN);
        }

        /**
         * Validate image with regular expression
         *
         * @param image image for validation
         * @return true valid image, false invalid image
         */
        public boolean validate(final String image) {

            matcher = pattern.matcher(image);
            return matcher.matches();

        }
    }

    /**
     * IP Address
     */
    public static class IPAddressValidator {

        private Pattern pattern;
        private Matcher matcher;

        private static final String IPADDRESS_PATTERN
                = "^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
                + "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
                + "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\."
                + "([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";

        public IPAddressValidator() {
            pattern = Pattern.compile(IPADDRESS_PATTERN);
        }

        /**
         * Validate ip address with regular expression
         *
         * @param ip ip address for validation
         * @return true valid ip address, false invalid ip address
         */
        public boolean validate(final String ip) {
            matcher = pattern.matcher(ip);
            return matcher.matches();
        }
    }

    /**
     * 7. Time Format
     */
    public static class Time12HoursValidator {

        private Pattern pattern;
        private Matcher matcher;

        private static final String TIME12HOURS_PATTERN
                = "(1[012]|[1-9]):[0-5][0-9](\\s)?(?i)(am|pm)";

        public Time12HoursValidator() {
            pattern = Pattern.compile(TIME12HOURS_PATTERN);
        }

        /**
         * Validate time in 12 hours format with regular expression
         *
         * @param time time address for validation
         * @return true valid time fromat, false invalid time format
         */
        public boolean validate(final String time) {
            matcher = pattern.matcher(time);
            return matcher.matches();
        }
    }

    /**
     * 8. Date Format
     */
    public static class DateValidator {

        private Pattern pattern;
        private Matcher matcher;

        private static final String DATE_PATTERN
                = "(0?[1-9]|[12][0-9]|3[01])/(0?[1-9]|1[012])/((19|20)\\d\\d)";

        public DateValidator() {
            pattern = Pattern.compile(DATE_PATTERN);
        }

        /**
         * Validate date format with regular expression
         *
         * @param date date address for validation
         * @return true valid date fromat, false invalid date format
         */
        public boolean validate(final String date) {

            matcher = pattern.matcher(date);

            if (matcher.matches()) {

                matcher.reset();

                if (matcher.find()) {

                    String day = matcher.group(1);
                    String month = matcher.group(2);
                    int year = Integer.parseInt(matcher.group(3));

                    if (day.equals("31")
                            && (month.equals("4") || month.equals("6") || month.equals("9")
                            || month.equals("11") || month.equals("04") || month.equals("06")
                            || month.equals("09"))) {
                        return false; // only 1,3,5,7,8,10,12 has 31 days
                    } else if (month.equals("2") || month.equals("02")) {
                        //leap year
                        if (year % 4 == 0) {
                            if (day.equals("30") || day.equals("31")) {
                                return false;
                            } else {
                                return true;
                            }
                        } else {
                            if (day.equals("29") || day.equals("30") || day.equals("31")) {
                                return false;
                            } else {
                                return true;
                            }
                        }
                    } else {
                        return true;
                    }
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    /**
     * 9. HTML Tag
     */
    public static class HTMLTagValidator {

        private Pattern pattern;
        private Matcher matcher;

        private static final String HTML_TAG_PATTERN = "<(\"[^\"]*\"|'[^']*'|[^'\">])*>";

        public HTMLTagValidator() {
            pattern = Pattern.compile(HTML_TAG_PATTERN);
        }

        /**
         * Validate html tag with regular expression
         *
         * @param tag html tag for validation
         * @return true valid html tag, false invalid html tag
         */
        public boolean validate(final String tag) {

            matcher = pattern.matcher(tag);
            return matcher.matches();

        }
    }

    /**
     * 10. HTML Links
     */
    public static class HTMLLinkExtractor {

        private Pattern patternTag, patternLink;
        private Matcher matcherTag, matcherLink;

        private static final String HTML_A_TAG_PATTERN = "(?i)<a([^>]+)>(.+?)</a>";
        private static final String HTML_A_HREF_TAG_PATTERN
                = "\\s*(?i)href\\s*=\\s*(\"([^\"]*\")|'[^']*'|([^'\">\\s]+))";

        public HTMLLinkExtractor() {
            patternTag = Pattern.compile(HTML_A_TAG_PATTERN);
            patternLink = Pattern.compile(HTML_A_HREF_TAG_PATTERN);
        }

        /**
         * Validate html with regular expression
         *
         * @param html html content for validation
         * @return Vector links and link text
         */
        public Vector<HtmlLink> grabHTMLLinks(final String html) {

            Vector<HtmlLink> result = new Vector<HtmlLink>();

            matcherTag = patternTag.matcher(html);

            while (matcherTag.find()) {

                String href = matcherTag.group(1); // href
                String linkText = matcherTag.group(2); // link text

                matcherLink = patternLink.matcher(href);

                while (matcherLink.find()) {

                    String link = matcherLink.group(1); // link
                    HtmlLink obj = new HtmlLink();
                    obj.setLink(link);
                    obj.setLinkText(linkText);

                    result.add(obj);

                }

            }

            return result;

        }

        public static class HtmlLink {

            String link;
            String linkText;

            HtmlLink() {
            }

            ;

		@Override
            public String toString() {
                return new StringBuffer("Link : ").append(this.link)
                        .append(" Link Text : ").append(this.linkText).toString();
            }

            public String getLink() {
                return link;
            }

            public void setLink(String link) {
                this.link = replaceInvalidChar(link);
            }

            public String getLinkText() {
                return linkText;
            }

            public void setLinkText(String linkText) {
                this.linkText = linkText;
            }

            private String replaceInvalidChar(String link) {
                link = link.replaceAll("'", "");
                link = link.replaceAll("\"", "");
                return link;
            }

        }
    }

    /**
     * 11. Function to quit.
     */
    public static void quit() {
        System.exit(0);
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        int choice = 0;
        System.out.println("CSE HW4 Regular Expressions API and Xeger.");

        while (choice != 11) {
            System.out.println("Choose an option: ");
            Scanner scanner = new Scanner(System.in);
            choice = scanner.nextInt();

            switch (choice) {

                case 1:

                    System.out.println("Enter a valid user name: ");
                    String username = scanner.next();
                    UsernameValidator uv = new UsernameValidator();
                    if (uv.validate(username)) {
                        System.out.println("Validates");
                    } else {
                        System.out.println("does not Validate");
                    }
                    break;

                case 2:
                    System.out.println("Enter a valid password: ");
                    username = scanner.next();
                    PasswordValidator pv = new PasswordValidator();
                    if (pv.validate(username)) {
                        System.out.println("Validates");
                    } else {
                        System.out.println("does not Validate");
                    }
                    break;

                case 3:
                    System.out.println("Enter a valid hex color code: ");
                    username = scanner.next();
                    HexValidator hv = new HexValidator();
                    if (hv.validate(username)) {
                        System.out.println("Validates");
                    } else {
                        System.out.println("does not Validate");
                    }
                    break;

                case 4:
                    System.out.println("Enter a valid Email: ");
                    username = scanner.next();
                    EmailValidator Ev = new EmailValidator();
                    if (Ev.validate(username)) {
                        System.out.println("Validates");
                    } else {
                        System.out.println("does not Validate");
                    }

                    break;

                case 5:
                    System.out.println("Enter a valid Image File Extension: ");
                    username = scanner.next();
                    ImageValidator Iv = new ImageValidator();
                    if (Iv.validate(username)) {
                        System.out.println("Validates");
                    } else {
                        System.out.println("does not Validate");
                    }

                    break;

                case 6:
                    System.out.println("Enter a valid IP Address: ");
                    username = scanner.next();
                    IPAddressValidator ipv = new IPAddressValidator();
                    if (ipv.validate(username)) {
                        System.out.println("Validates");
                    } else {
                        System.out.println("does not Validate");
                    }

                    break;

                case 7:

                    System.out.println("Enter a valid Time Format: ");
                    username = scanner.next();
                    Time12HoursValidator tv = new Time12HoursValidator();
                    if (tv.validate(username)) {
                        System.out.println("Validates");
                    } else {
                        System.out.println("does not Validate");
                    }
                    break;

                case 8:
                    System.out.println("Enter a valid Date Format: ");
                    username = scanner.next();
                    DateValidator dv = new DateValidator();
                    if (dv.validate(username)) {
                        System.out.println("Validates");
                    } else {
                        System.out.println("does not Validate");
                    }
                    break;

                case 9:
                    System.out.println("Enter a valid HTML Tag: ");
                    username = scanner.next();
                    HTMLTagValidator htv = new HTMLTagValidator();
                    if (htv.validate(username)) {
                        System.out.println("Validates");
                    } else {
                        System.out.println("does not Validate");
                    }
                    break;

                case 10:
                    System.out.println("Enter a valid HTML Link: ");
                    username = scanner.next();
                    HTMLLinkExtractor hte = new HTMLLinkExtractor();
                    Vector v = hte.grabHTMLLinks(username);
                    System.out.print(((HTMLLinkExtractor.HtmlLink) v.get(0)).toString());
                    break;

                case 11:
                    quit();
                    break;

            }

        }

    }

}

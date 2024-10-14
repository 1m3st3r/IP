import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.Stack;
import java.util.StringTokenizer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class Main {

    public static boolean isOperator(char c) {
        return c == '+' || c == '-' || c == '*' || c == '/';
    }

    public static boolean isValidExpression(String expr) {
        Stack<Character> stack = new Stack<>();
        for (int i = 0; i < expr.length(); i++) {
            char c = expr.charAt(i);
            if (c == '(') {
                stack.push(c);
            } 
            else if (c == ')') {
                if (stack.isEmpty() || stack.pop() != '(') {
                    return false;
                }
            }
        }
        return stack.isEmpty();
    }

    public static double performOperation(char operator, double a, double b) {
        switch (operator) {
            case '+':
                return a + b;
            case '-':
                return a - b;
            case '*':
                return a * b;
            case '/':
                if (b == 0) {
                    throw new UnsupportedOperationException("Cannot divide by zero");
                }
                return a / b;
            case '~':
                return -a;
        }
        return 0;
    }

    public static int getPriority(char operator) {
        switch (operator) {
            case '*':
            case '/':
                return 2;
            case '+':
            case '-':
                return 1;
            case '~':
                return 3;
        }
        return 0;
    }

    public static double evaluateExpression(String expr) {
        Stack<Double> values = new Stack<>();
        Stack<Character> operators = new Stack<>();
        int unaryMinusCount = 0;
        for (int i = 0; i < expr.length(); i++) {
            char c = expr.charAt(i);

            if (c == ' ') continue;

            if (Character.isDigit(c) || c == '.') {
                StringBuilder sb = new StringBuilder();
                while (i < expr.length() && (Character.isDigit(expr.charAt(i)) || expr.charAt(i) == '.')) {
                    sb.append(expr.charAt(i));
                    i++;
                }
                i--;
                values.push(Double.parseDouble(sb.toString()));
                if (unaryMinusCount > 0) {
                    for (int j = 0; j < unaryMinusCount; j++) {
                        values.push(values.pop() * -1);
                    }
                    unaryMinusCount = 0;
                }
            } 
            else if (c == '(') {
                operators.push(c);
                if (unaryMinusCount > 0) {
                    unaryMinusCount = 0;
                }
            } 
            else if (c == ')') {
                while (operators.peek() != '(') {
                    double val2 = values.pop();
                    double val1 =values.pop();
                    char op = operators.pop();
                    values.push(performOperation(op, val1, val2));
                }
                operators.pop();
                if (unaryMinusCount > 0) {
                    for (int j = 0; j < unaryMinusCount; j++) {
                        values.push(values.pop() * -1);
                    }
                    unaryMinusCount = 0;
                }
            } 
            else if (c == '~') {
                unaryMinusCount++;
            } 
            else if (isOperator(c)) {
                while (!operators.isEmpty() && isOperator(operators.peek()) && getPriority(c) <= getPriority(operators.peek())) {
                    double val2 = values.pop();
                    double val1 = values.pop();
                    char op = operators.pop();
                    values.push(performOperation(op, val1, val2));
                }
                operators.push(c);
                if (unaryMinusCount > 0) {
                    unaryMinusCount = 0;
                }
            }
        }    
        while (!operators.isEmpty()) {
            double val2 = values.pop();
            double val1 = values.pop();
            char op = operators.pop();
            values.push(performOperation(op, val1, val2));
        }
        return values.pop();
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the file name: ");
        String fileName = scanner.nextLine();
        String expr;
        if (fileName.endsWith(".txt")) {
            FileReader input = new FileReader(fileName);
            StringBuilder sb = new StringBuilder();
            int i;
            while ((i = input.read()) != -1) {
                sb.append((char) i);
            }
            input.close();
            expr = sb.toString();
        } 
        else if (fileName.endsWith(".xml")) {
            FileReader input = new FileReader(fileName);
            StringBuilder sb = new StringBuilder();
            int i;
            while ((i = input.read()) != -1) {
                sb.append((char) i);
            }
            input.close();
            String xml = sb.toString();
            int start = xml.indexOf("<expr>") + "<expr>".length();
            int end = xml.indexOf("</expr>");
            expr = xml.substring(start, end);
        } 
        else if (fileName.endsWith(".json")) {
            FileReader input = new FileReader(fileName);
            StringBuilder sb = new StringBuilder();
            int i;
            while ((i = input.read()) != -1) {
                sb.append((char) i);
            }
            input.close();
            String json = sb.toString();
            int start = json.indexOf("\"expr\":") + "\"expr\":".length();
            int end = json.indexOf("}");
            expr = json.substring(start, end);
        } 
        else {
            throw new IllegalArgumentException("Invalid file format. Only .txt, .xml and .json are supported.");
        }
        double result = 0.0;
        if(isValidExpression(expr)) {
            result = evaluateExpression(expr);
        }
        else {
            System.out.println("Invalid expression.");
            return;
        }
        System.out.print("Do you want to archive the output files? (y/n): ");
        String archiveChoice = scanner.nextLine();
        if (archiveChoice.equalsIgnoreCase("y")) {
            ZipOutputStream zipOutput = new ZipOutputStream(new FileOutputStream("output.zip"));
            zipOutput.putNextEntry(new ZipEntry("output.txt"));
            zipOutput.write(Double.toString(result).getBytes());
            zipOutput.closeEntry();
            zipOutput.putNextEntry(new ZipEntry("output.xml"));
            zipOutput.write(("<result>" + Double.toString(result) + "</result>").getBytes());
            zipOutput.closeEntry();
            zipOutput.putNextEntry(new ZipEntry("output.json"));
            zipOutput.write(("{\"result\":" + Double.toString(result) + "}").getBytes());
            zipOutput.closeEntry();
            zipOutput.close();
        } else {
            FileWriter outputTXT = new FileWriter("output.txt");
            outputTXT.write(Double.toString(result));
            outputTXT.close();

            FileWriter outputXML = new FileWriter("output.xml");
            outputXML.write("<result>" + Double.toString(result) + "</result>");
            outputXML.close();

            FileWriter outputJSON = new FileWriter("output.json");
            outputJSON.write("{\"result\":" + Double.toString(result) + "}");
            outputJSON.close();
        }

        System.out.print("Do you want to encrypt the output files? (y/n): ");
        String encryptChoice = scanner.nextLine();
        if (encryptChoice.equalsIgnoreCase("y")) {
            String password = "qwerty";
            byte[] salt = { (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32, (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03 };
            int iterationCount = 19;

            PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
            SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

            Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");

            pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

            FileOutputStream outputTXT = new FileOutputStream("output.txt");
            FileOutputStream outputXML = new FileOutputStream("output.xml");
            FileOutputStream outputJSON = new FileOutputStream("output.json");

            CipherOutputStream cipherOutputTXT = new CipherOutputStream(outputTXT, pbeCipher);
            CipherOutputStream cipherOutputXML = new CipherOutputStream(outputXML, pbeCipher);
            CipherOutputStream cipherOutputJSON = new CipherOutputStream(outputJSON, pbeCipher);

            cipherOutputTXT.write(Double.toString(result).getBytes());
            cipherOutputXML.write(("<result>" + Double.toString(result) + "</result>").getBytes());
            cipherOutputJSON.write(("{\"result\":" + Double.toString(result) + "}").getBytes());

            cipherOutputTXT.close();
            cipherOutputXML.close();
            cipherOutputJSON.close();
        }
    }
}
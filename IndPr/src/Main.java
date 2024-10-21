import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.FileInputStream;
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
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.yaml.snakeyaml.Yaml;
import java.util.Map;
import javax.swing.*;

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

    public static List<String> extractExpressions(String expr) {
        List<String> extractedExpressions = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (char c : expr.toCharArray()) {
            if (Character.isDigit(c) || isOperator(c) || c == '~' || c == '.' || c == ' ' || c == '(' || c == ')') {
                current.append(c);
            } else {
                if (current.length() > 0) {
                    extractedExpressions.add(current.toString().trim());
                    current.setLength(0);
                }
            }
        }
        if (current.length() > 0) {
            extractedExpressions.add(current.toString().trim());
        }
        return extractedExpressions;
    }

    public static List<String> extractExpressionsUsingRegex(String expr) {
        String[] matches = expr.split("[^0-9.+*/~() ]+");
        List<String> expressions = new ArrayList<>();
        for (String match : matches) {
            if (!match.trim().isEmpty()) {
                expressions.add(match.trim());
            }
        }
        return expressions;
    }
    
    private static String readExpressionFromFile(String fileName) throws IOException {
        StringBuilder sb = new StringBuilder();
        
        if (fileName.endsWith(".txt") || fileName.endsWith(".xml") || fileName.endsWith(".json") || fileName.endsWith(".html") || fileName.endsWith(".yaml") || fileName.endsWith(".yml")) {
            try (FileReader input = new FileReader(fileName)) {
                // Обработка для YAML
                if (fileName.endsWith(".yaml") || fileName.endsWith(".yml")) {
                    Yaml yaml = new Yaml();
                    try (FileReader reader = new FileReader(fileName)) {
                        Map<String, String> data = yaml.load(reader);
                        return data.get("expr"); 
                        // Предполагая, что YAML имеет формат {expr: "some_expression"}
                    }
                }
                // Обработка для HTML
                else if (fileName.endsWith(".html")) {
                    int i;
                    while ((i = input.read()) != -1) {
                        sb.append((char) i);
                    }
                    String html = sb.toString();
                    int start = html.indexOf("<expr>") + "<expr>".length();
                    int end = html.indexOf("</expr>");
                    if (start > -1 && end > -1) {
                        return html.substring(start, end);
                    } else {
                        throw new IllegalArgumentException("<expr> tag not found in HTML file.");
                    }
                } 
                // Обработка для XML
                else if (fileName.endsWith(".xml")) {
                    int i;
                    while ((i = input.read()) != -1) {
                        sb.append((char) i);
                    }
                    String xml = sb.toString();
                    int start = xml.indexOf("<expr>") + "<expr>".length();
                    int end = xml.indexOf("</expr>");
                    return xml.substring(start, end);
                } 
                // Обработка для JSON
                else if (fileName.endsWith(".json")) {
                    int i;
                    while ((i = input.read()) != -1) {
                        sb.append((char) i);
                    }
                    String json = sb.toString();
                    int start = json.indexOf("\"expr\":") + "\"expr\":".length();
                    int end = json.indexOf("}");
                    return json.substring(start, end).replace("\"", "").trim();
                } 
                // Обработка для текстового файла
                else {
                    int i;
                    while ((i = input.read()) != -1) {
                        sb.append((char) i);
                    }
                    return sb.toString();
                }
            }
        } else {
            throw new IllegalArgumentException("Invalid file format. Only .txt, .xml, .json, .html, .yaml and .yml are supported.");
        }
    }
    
    private static String readExpressionFromYamlFile(String fileName) throws IOException {
        Yaml yaml = new Yaml();
        try (FileReader reader = new FileReader(fileName)) {
            Map<String, String> data = yaml.load(reader);
            return data.get("expr"); // Предполагая, что YAML имеет формат {expr: "some_expression"}
        }
    }

    private static void processExpressions(List<String> expressions, StringBuilder output) {
        for (String expression : expressions) {
            if (isValidExpression(expression)) {
                double result = evaluateExpression(expression);
                output.append(expression).append(" = ").append(result).append("\n");
            } else {
                output.append(expression).append(" is invalid\n");
            }
        }
    }

    private static void writeOutputFiles(String output, String outputRegex) throws IOException {
        // Запись результатов в файлы
        try (FileWriter outputTXT = new FileWriter("output.txt")) {
            outputTXT.write(output);
        }

        try (FileWriter outputXML = new FileWriter("output.xml")) {
            outputXML.write("<results>\n" + output + "\n</results>");
        }

        try (FileWriter outputJSON = new FileWriter("output.json")) {
            outputJSON.write("{\"results\": \"" + output.replace("\n", "\\n").replace("\"", "\\\"") + "\"}");
        }

        // Создание HTML файла
        try (FileWriter outputHTML = new FileWriter("output.html")) {
            outputHTML.write("<html>\n<head>\n<title>Output Results</title>\n</head>\n<body>\n");
            outputHTML.write("<h1>Output Results</h1>\n<pre>\n");
            outputHTML.write(output);
            outputHTML.write("</pre>\n</body>\n</html>");
        }
    }

    private static void archiveOutputFiles(Scanner scanner) throws IOException {
        System.out.print("Do you want to archive the output files? (y/n): ");
        String archiveChoice = scanner.nextLine();
        if (archiveChoice.equalsIgnoreCase("y")) {
            try (ZipOutputStream zipOutput = new ZipOutputStream(new FileOutputStream("output.zip"))) {
                addFileToZip(zipOutput, "output.txt");
                addFileToZip(zipOutput, "output.xml");
                addFileToZip(zipOutput, "output.json");
            }
        }
    }

    private static void addFileToZip(ZipOutputStream zipOutput, String fileName) throws IOException {
        zipOutput.putNextEntry(new ZipEntry(fileName));
        try (FileInputStream fis = new FileInputStream(fileName)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = fis.read(buffer)) >= 0) {
                zipOutput.write(buffer, 0, length);
            }
        }
        zipOutput.closeEntry();
    }

    private static void encryptOutputFiles(Scanner scanner) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
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
            
            encryptFile("output.txt", pbeCipher);
            encryptFile("output.xml", pbeCipher);
            encryptFile("output.json", pbeCipher);
            encryptFile("output.html", pbeCipher);
            encryptFile("output.yaml", pbeCipher);
        }
    }

    private static void encryptFile(String fileName, Cipher cipher) throws IOException {
        try (FileInputStream fis = new FileInputStream(fileName);
             FileOutputStream fos = new FileOutputStream("encrypted_" + fileName);
             CipherOutputStream cipherOutput = new CipherOutputStream(fos, cipher)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = fis.read(buffer)) >= 0) {
                cipherOutput.write(buffer, 0, length);
            }
        }
    }
    
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        // Создание графического интерфейса
        JFrame frame = new JFrame("My Expression");
        frame.setSize(400, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(null);

        JLabel fileNameLabel = new JLabel("Enter the file name:");
        fileNameLabel.setBounds(10, 10, 200, 25);
        frame.add(fileNameLabel);

        JTextField fileNameField = new JTextField();
        fileNameField.setBounds(10, 40, 280, 25);
        frame.add(fileNameField);

        JCheckBox archiveCheckBox = new JCheckBox("Archive output files");
        archiveCheckBox.setBounds(10, 70, 200, 25);
        frame.add(archiveCheckBox);

        JCheckBox encryptCheckBox = new JCheckBox("Encrypt output files");
        encryptCheckBox.setBounds(10, 100, 200, 25);
        frame.add(encryptCheckBox);

        JButton evaluateButton = new JButton("Enter");
        evaluateButton.setBounds(300, 40, 80, 25);
        frame.add(evaluateButton);

        JTextArea resultArea = new JTextArea();
        resultArea.setBounds(10, 140, 370, 200);
        resultArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(resultArea);
        scrollPane.setBounds(10, 140, 370, 200);
        frame.add(scrollPane);

        evaluateButton.addActionListener(e -> {
            try {
                String fileName = fileNameField.getText();
                String expr = readExpressionFromFile(fileName);

                if (expr == null || !isValidExpression(expr)) {
                    resultArea.setText("Invalid expression.");
                    return;
                }

                // Извлечение выражений
                List<String> expressions = extractExpressions(expr);
                List<String> expressionsRegex = extractExpressionsUsingRegex(expr);

                // Обработка выражений
                StringBuilder output = new StringBuilder();
                processExpressions(expressions, output);

                StringBuilder outputRegex = new StringBuilder();
                processExpressions(expressionsRegex, outputRegex);

                // Запись в выходные файлы
                writeOutputFiles(output.toString(), outputRegex.toString());
                resultArea.setText("Results calculated and written to files.");

                if (archiveCheckBox.isSelected()) {
                    try (ZipOutputStream zipOutput = new ZipOutputStream(new FileOutputStream("output.zip"))) {
                        addFileToZip(zipOutput, "output.txt");
                        addFileToZip(zipOutput, "output.xml");
                        addFileToZip(zipOutput, "output.json");
                    }
                }

                if (encryptCheckBox.isSelected()) {
                    String password = "qwerty";
                    byte[] salt = {(byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32, (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03};
                    int iterationCount = 19;

                    PBEParameterSpec pbeParamSpec = new PBEParameterSpec(salt, iterationCount);
                    PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
                    SecretKeyFactory keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
                    SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

                    Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");
                    pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

                    encryptFile("output.txt", pbeCipher);
                    encryptFile("output.xml", pbeCipher);
                    encryptFile("output.json", pbeCipher);
                }

            } catch (Exception ex) {
                resultArea.setText("Error: " + ex.getMessage());
            }
        });

        frame.setVisible(true);
    }
}
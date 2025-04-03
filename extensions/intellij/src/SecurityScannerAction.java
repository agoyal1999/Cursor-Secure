package com.cursorsecure.intellij;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.psi.PsiFile;
import com.intellij.psi.PsiManager;
import org.jetbrains.annotations.NotNull;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * IntelliJ Plugin action for the Cursor Secure scanner
 */
public class SecurityScannerAction extends AnAction {

    @Override
    public void actionPerformed(@NotNull AnActionEvent event) {
        Project project = event.getProject();
        if (project == null) {
            return;
        }

        // Get current file
        Editor editor = FileEditorManager.getInstance(project).getSelectedTextEditor();
        if (editor == null) {
            return;
        }

        Document document = editor.getDocument();
        VirtualFile file = FileDocumentManager.getInstance().getFile(document);
        if (file == null) {
            return;
        }

        String filePath = file.getPath();
        String fileContent = document.getText();
        String fileExtension = file.getExtension();

        // Map file extension to language
        String language = mapExtensionToLanguage(fileExtension);
        if (language == null) {
            // Unsupported language
            return;
        }

        // Run scan
        List<VulnerabilityResult> results = scanFile(filePath, fileContent, language);
        
        // Display results
        displayResults(project, results, file);
    }

    private String mapExtensionToLanguage(String extension) {
        if (extension == null) {
            return null;
        }
        
        switch (extension.toLowerCase()) {
            case "js":
            case "jsx":
            case "ts":
            case "tsx":
                return "javascript";
            case "py":
                return "python";
            case "java":
                return "java";
            case "cs":
                return "csharp";
            default:
                return null;
        }
    }

    private List<VulnerabilityResult> scanFile(String filePath, String content, String language) {
        List<VulnerabilityResult> results = new ArrayList<>();
        
        try {
            // Build command to call the CLI scanner
            ProcessBuilder processBuilder = new ProcessBuilder(
                "node", 
                System.getProperty("user.home") + "/.cursor-secure/cli.js", 
                "scan",
                "--format", "json",
                filePath
            );
            
            Process process = processBuilder.start();
            
            // Get the output
            String output = new BufferedReader(new InputStreamReader(process.getInputStream()))
                .lines()
                .collect(Collectors.joining("\n"));
            
            // TODO: Parse output to VulnerabilityResult objects
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                // Handle error
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return results;
    }

    private void displayResults(Project project, List<VulnerabilityResult> results, VirtualFile file) {
        // Convert to IntelliJ annotations/highlights
        PsiFile psiFile = PsiManager.getInstance(project).findFile(file);
        if (psiFile == null) {
            return;
        }
        
        // TODO: Add annotations to the editor
    }

    // Simple data class for vulnerability results
    private static class VulnerabilityResult {
        private String ruleId;
        private String message;
        private String severity;
        private int line;
        private int column;
        private String fix;
        
        // Getters and setters
    }
} 
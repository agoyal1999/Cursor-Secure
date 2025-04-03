package com.cursorsecure.eclipse.handlers;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.eclipse.core.commands.AbstractHandler;
import org.eclipse.core.commands.ExecutionEvent;
import org.eclipse.core.commands.ExecutionException;
import org.eclipse.core.resources.IFile;
import org.eclipse.core.resources.IMarker;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.text.IDocument;
import org.eclipse.ui.IEditorInput;
import org.eclipse.ui.IEditorPart;
import org.eclipse.ui.IWorkbenchPage;
import org.eclipse.ui.IWorkbenchWindow;
import org.eclipse.ui.PlatformUI;
import org.eclipse.ui.handlers.HandlerUtil;
import org.eclipse.ui.part.FileEditorInput;
import org.eclipse.ui.texteditor.ITextEditor;

/**
 * Handler for scanning the current file for security vulnerabilities
 */
public class ScanHandler extends AbstractHandler {

    @Override
    public Object execute(ExecutionEvent event) throws ExecutionException {
        IWorkbenchWindow window = HandlerUtil.getActiveWorkbenchWindowChecked(event);
        
        // Get current editor and file
        IWorkbenchPage page = window.getActivePage();
        IEditorPart editor = page.getActiveEditor();
        
        if (editor == null) {
            MessageDialog.openInformation(window.getShell(), "Security Scanner", 
                    "No file is currently open for editing.");
            return null;
        }
        
        IEditorInput input = editor.getEditorInput();
        if (!(input instanceof FileEditorInput)) {
            MessageDialog.openInformation(window.getShell(), "Security Scanner", 
                    "The current editor does not contain a file.");
            return null;
        }
        
        IFile file = ((FileEditorInput) input).getFile();
        String filePath = file.getLocation().toOSString();
        String fileExtension = file.getFileExtension();
        
        // Get file content
        String fileContent = "";
        if (editor instanceof ITextEditor) {
            IDocument document = ((ITextEditor) editor).getDocumentProvider().getDocument(input);
            fileContent = document.get();
        }
        
        // Map file extension to language
        String language = mapExtensionToLanguage(fileExtension);
        if (language == null) {
            MessageDialog.openInformation(window.getShell(), "Security Scanner", 
                    "The file type is not supported by the security scanner.");
            return null;
        }
        
        // Run scan
        List<VulnerabilityResult> results = scanFile(filePath, fileContent, language);
        
        // Display results
        displayResults(file, results);
        
        // Show a message
        MessageDialog.openInformation(window.getShell(), "Security Scanner", 
                "Scan completed. Found " + results.size() + " vulnerabilities.");
        
        return null;
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
    
    private void displayResults(IFile file, List<VulnerabilityResult> results) {
        try {
            // Clear existing markers
            file.deleteMarkers("com.cursorsecure.eclipse.markers.securityVulnerability", true, IResource.DEPTH_ZERO);
            
            // Create new markers
            for (VulnerabilityResult result : results) {
                IMarker marker = file.createMarker("com.cursorsecure.eclipse.markers.securityVulnerability");
                marker.setAttribute(IMarker.MESSAGE, result.message);
                marker.setAttribute(IMarker.LINE_NUMBER, result.line);
                marker.setAttribute(IMarker.SEVERITY, getSeverity(result.severity));
                marker.setAttribute("ruleId", result.ruleId);
                marker.setAttribute("severity", result.severity);
            }
        } catch (CoreException e) {
            e.printStackTrace();
        }
    }
    
    private int getSeverity(String severity) {
        switch (severity) {
            case "critical":
            case "high":
                return IMarker.SEVERITY_ERROR;
            case "warning":
                return IMarker.SEVERITY_WARNING;
            case "info":
                return IMarker.SEVERITY_INFO;
            default:
                return IMarker.SEVERITY_WARNING;
        }
    }
    
    // Simple data class for vulnerability results
    private static class VulnerabilityResult {
        private String ruleId;
        private String message;
        private String severity;
        private int line;
        private int column;
        private String fix;
    }
} 
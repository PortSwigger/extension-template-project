import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import ui.BorborBorpMainPanel;


public class Extension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi montoyaApi) {
        montoyaApi.extension().setName("BorborBorp");
        montoyaApi.userInterface().registerSuiteTab("Borp!", new BorborBorpMainPanel());
    }
}
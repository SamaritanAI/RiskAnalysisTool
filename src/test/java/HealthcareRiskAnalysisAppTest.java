import com.infosec.riskanalysistool.HealthcareRiskAnalysisApp;
import javafx.scene.control.TableView;
import javafx.scene.input.KeyCode;
import javafx.stage.Stage;
import org.junit.jupiter.api.*;
import org.testfx.framework.junit5.ApplicationTest;
import static org.testfx.assertions.api.Assertions.*;

public class HealthcareRiskAnalysisAppTest extends ApplicationTest {
    private HealthcareRiskAnalysisApp app;

    @Override
    public void start(Stage stage) throws Exception {
        app = new HealthcareRiskAnalysisApp();
        app.start(stage);
    }

    @Test
    public void testAddRisk() {
        // Enter threat description
        clickOn("#threatField").write("Unauthorised access to patient records");

        // Select HIPAA Rule
        clickOn("#hipaaRuleCombo").type(KeyCode.DOWN).type(KeyCode.ENTER);

        // Select RMF Step
        clickOn("#rmfStepCombo").type(KeyCode.DOWN).type(KeyCode.DOWN).type(KeyCode.ENTER);

        // Enter Impact
        clickOn("#impactField").write("7");

        // Enter Likelihood
        clickOn("#likelihoodField").write("5");

        // Enter SLE
        clickOn("#sleField").write("50000");

        // Enter ARO
        clickOn("#aroField").write("0.2");

        // Click Add Risk
        clickOn("#addRiskButton");

        // Switch to Risk Analysis tab
        clickOn(".tab").lookup("Risk Analysis").query();

        // Verify that the risk has been added to the table
        TableView<HealthcareRiskAnalysisApp.Risk> riskTable = lookup("#riskTable").queryTableView();
        assertThat(riskTable.getItems()).hasSize(1);

        // Verify the content of the first risk
        HealthcareRiskAnalysisApp.Risk risk = riskTable.getItems().get(0);
        assertThat(risk.getThreat()).isEqualTo("Unauthorised access to patient records");
        assertThat(risk.getImpact()).isEqualTo(7);
        assertThat(risk.getLikelihood()).isEqualTo(5);
        assertThat(risk.getSingleLossExpectancy()).isEqualTo(50000.0);
        assertThat(risk.getannualisedRateOfOccurrence()).isEqualTo(0.2);

        // Verify calculated values
        assertThat(risk.getRiskPriorityNumber()).isEqualTo(35);
        assertThat(risk.getannualisedLossExpectancy()).isEqualTo(10000.0);
    }

    @Test
    public void testAddInvalidRisk() {
        // Enter threat description
        clickOn("#threatField").write("Invalid Risk");

        // Select HIPAA Rule
        clickOn("#hipaaRuleCombo").type(KeyCode.DOWN).type(KeyCode.ENTER);

        // Select RMF Step
        clickOn("#rmfStepCombo").type(KeyCode.DOWN).type(KeyCode.ENTER);

        // Enter Invalid Impact
        clickOn("#impactField").write("11");

        // Enter Likelihood
        clickOn("#likelihoodField").write("5");

        // Enter SLE
        clickOn("#sleField").write("1000");

        // Enter ARO
        clickOn("#aroField").write("0.1");

        // Click Add Risk
        clickOn("#addRiskButton");

        // Verify that no risk has been added to the table
        TableView<HealthcareRiskAnalysisApp.Risk> riskTable = lookup("#riskTable").queryTableView();
        assertThat(riskTable.getItems()).isEmpty();
    }
}
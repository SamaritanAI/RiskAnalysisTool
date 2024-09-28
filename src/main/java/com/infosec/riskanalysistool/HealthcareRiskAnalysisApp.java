package com.infosec.riskanalysistool;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.Parent;
import javafx.scene.layout.*;
import javafx.scene.control.*;
import javafx.scene.chart.*;
import javafx.collections.*;
import javafx.stage.Stage;
import javafx.beans.property.*;
import javafx.geometry.Insets;
import java.util.List;

public class HealthcareRiskAnalysisApp extends Application {

    //UI Components
    private TabPane mainTabPane;

    //Risk Entry Tab Components
    private TextField threatField;
    private ComboBox<HIPAARule> hipaaRuleCombo;
    private ComboBox<RMFStep> rmfStepCombo;
    private TextField impactField;
    private TextField likelihoodField;
    private Button addRiskButton;

    //Risk Analysis Tab Components
    private TableView<Risk> riskTable;
    private BarChart<String, Number> riskChart;


    private ObservableList<Risk> risks;

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Healthcare Risk Analysis Tool");

        //Initialise data
        risks = FXCollections.observableArrayList();

        //Initialise UI Components
        initialiseUI();

        //Set up Scene and Stage
        Scene scene = new Scene(mainTabPane, 1080, 720);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void initialiseUI() {
        //Main TabPane
        mainTabPane = new TabPane();

        //Risk Entry Tab
        Tab riskEntryTab = new Tab("Risk Entry");
        riskEntryTab.setContent(createRiskEntryContent());
        riskEntryTab.setClosable(false);

        //Risk Analysis Tab
        Tab riskAnalysisTab = new Tab("Risk Analysis");
        riskAnalysisTab.setContent(createRiskAnalysisContent());
        riskAnalysisTab.setClosable(false);

        mainTabPane.getTabs().addAll(riskEntryTab, riskAnalysisTab);
    }

    private Parent createRiskEntryContent() {
        //Create UI components for Risk Entry
        threatField = new TextField();
        hipaaRuleCombo = new ComboBox<>();
        rmfStepCombo = new ComboBox<>();
        impactField = new TextField();
        likelihoodField = new TextField();
        addRiskButton = new Button("Add Risk");

        //Set ComboBox items
        hipaaRuleCombo.getItems().setAll(HIPAARule.values());
        rmfStepCombo.getItems().setAll(RMFStep.values());

        //Set up layout
        GridPane grid = new GridPane();
        grid.setVgap(10);
        grid.setHgap(10);
        grid.setPadding(new Insets(20));

        grid.add(new Label("Threat:"), 0, 0);
        grid.add(threatField, 1, 0);
        grid.add(new Label("HIPAA Rule:"), 0, 1);
        grid.add(hipaaRuleCombo, 1, 1);
        grid.add(new Label("RMF Step:"), 0, 2);
        grid.add(rmfStepCombo, 1, 2);
        grid.add(new Label("Impact (1-10):"), 0, 3);
        grid.add(impactField, 1, 3);
        grid.add(new Label("Likelihood (1-10):"), 0, 4);
        grid.add(likelihoodField, 1, 4);
        grid.add(addRiskButton, 1, 5);

        //Set up event handler
        addRiskButton.setOnAction(e -> handleAddRisk());

        return grid;
    }

    private Parent createRiskAnalysisContent() {
        //Create UI components for Risk Analysis
        riskTable = new TableView<>();
        riskChart = new BarChart<>(new CategoryAxis(), new NumberAxis());

        //Set up riskTable columns
        setupRiskTable();

        //Layout
        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(20));
        vbox.getChildren().addAll(riskTable, riskChart);

        //Update analysis
        updateAnalysis();

        return vbox;
    }

    private void handleAddRisk() {
        try {
            String threat = threatField.getText();
            HIPAARule hipaaRule = hipaaRuleCombo.getValue();
            RMFStep rmfStep = rmfStepCombo.getValue();
            int impact = Integer.parseInt(impactField.getText());
            int likelihood = Integer.parseInt(likelihoodField.getText());

            Risk risk = new Risk(threat, hipaaRule, rmfStep, impact, likelihood);

            if (ValidationUtil.isValidRisk(risk)) {
                risks.add(risk);
                clearRiskEntryFields();
                updateAnalysis();
            } else {
                // Handle invalid risk (e.g., show an alert)
                showAlert("Invalid Risk Entry", "Please ensure all fields are filled correctly.");
            }
        } catch (NumberFormatException ex) {
            showAlert("Invalid Input", "Impact and Likelihood must be integers between 1 and 10.");
        }
    }

    private void clearRiskEntryFields() {
        threatField.clear();
        hipaaRuleCombo.getSelectionModel().clearSelection();
        rmfStepCombo.getSelectionModel().clearSelection();
        impactField.clear();
        likelihoodField.clear();
    }

    private void setupRiskTable() {
        TableColumn<Risk, String> threatColumn = new TableColumn<>("Threat");
        threatColumn.setCellValueFactory(data -> data.getValue().threatProperty());

        TableColumn<Risk, String> hipaaRuleColumn = new TableColumn<>("HIPAA Rule");
        hipaaRuleColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getHipaaRule().toString()));

        TableColumn<Risk, String> rmfStepColumn = new TableColumn<>("RMF Step");
        rmfStepColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().getRmfStep().toString()));

        TableColumn<Risk, Integer> impactColumn = new TableColumn<>("Impact");
        impactColumn.setCellValueFactory(data -> data.getValue().impactProperty().asObject());

        TableColumn<Risk, Integer> likelihoodColumn = new TableColumn<>("Likelihood");
        likelihoodColumn.setCellValueFactory(data -> data.getValue().likelihoodProperty().asObject());

        TableColumn<Risk, Integer> riskScoreColumn = new TableColumn<>("Risk Score");
        riskScoreColumn.setCellValueFactory(data -> data.getValue().riskScoreProperty().asObject());

        riskTable.getColumns().addAll(threatColumn, hipaaRuleColumn, rmfStepColumn, impactColumn, likelihoodColumn, riskScoreColumn);
        riskTable.setItems(risks);
    }

    private void updateAnalysis() {
        //The riskTable updates automatically because it's bound to the ObservableList 'risks'

        //Update the riskChart
        ChartUtil.updateRiskChart(riskChart, risks);
    }

    private void showAlert(String title, String content) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(content);
        alert.showAndWait();
    }

    //Enums
    public enum HIPAARule {
        PRIVACY_RULE, SECURITY_RULE, BREACH_NOTIFICATION_RULE
    }

    public enum RMFStep {
        CATEGORIZE, SELECT, IMPLEMENT, ASSESS, AUTHORIZE, MONITOR
    }

    // Risk Class
    public class Risk {
        private SimpleStringProperty threat;
        private ObjectProperty<HIPAARule> hipaaRule;
        private ObjectProperty<RMFStep> rmfStep;
        private SimpleIntegerProperty impact;
        private SimpleIntegerProperty likelihood;
        private SimpleIntegerProperty riskScore;

        public Risk(String threat, HIPAARule hipaaRule, RMFStep rmfStep, int impact, int likelihood) {
            this.threat = new SimpleStringProperty(threat);
            this.hipaaRule = new SimpleObjectProperty<>(hipaaRule);
            this.rmfStep = new SimpleObjectProperty<>(rmfStep);
            this.impact = new SimpleIntegerProperty(impact);
            this.likelihood = new SimpleIntegerProperty(likelihood);
            this.riskScore = new SimpleIntegerProperty(calculateRiskScore());
        }

        public String getThreat() {
            return threat.get();
        }

        public SimpleStringProperty threatProperty() {
            return threat;
        }

        public HIPAARule getHipaaRule() {
            return hipaaRule.get();
        }

        public ObjectProperty<HIPAARule> hipaaRuleProperty() {
            return hipaaRule;
        }

        public RMFStep getRmfStep() {
            return rmfStep.get();
        }

        public ObjectProperty<RMFStep> rmfStepProperty() {
            return rmfStep;
        }

        public int getImpact() {
            return impact.get();
        }

        public SimpleIntegerProperty impactProperty() {
            return impact;
        }

        public int getLikelihood() {
            return likelihood.get();
        }

        public SimpleIntegerProperty likelihoodProperty() {
            return likelihood;
        }

        public int getRiskScore() {
            return riskScore.get();
        }

        public SimpleIntegerProperty riskScoreProperty() {
            return riskScore;
        }

        private int calculateRiskScore() {
            return getImpact() * getLikelihood();
        }
    }

    //Validation Utility Class
    public static class ValidationUtil {
        public static boolean isValidRisk(Risk risk) {
            return risk != null &&
                    risk.getThreat() != null && !risk.getThreat().isEmpty() &&
                    risk.getHipaaRule() != null &&
                    risk.getRmfStep() != null &&
                    risk.getImpact() >= 1 && risk.getImpact() <= 10 &&
                    risk.getLikelihood() >= 1 && risk.getLikelihood() <= 10;
        }
    }

    //Chart Utility Class
    public static class ChartUtil {
        public static void updateRiskChart(BarChart<String, Number> chart, List<Risk> risks) {
            XYChart.Series<String, Number> series = new XYChart.Series<>();
            series.setName("Risk Scores");

            for (Risk risk : risks) {
                series.getData().add(new XYChart.Data<>(risk.getThreat(), risk.getRiskScore()));
            }

            chart.getData().clear();
            chart.getData().add(series);
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}

//TODO add functionality to export results.
//TODO fix functionality for testing the app.

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
import javafx.util.StringConverter;

import java.util.List;
import java.text.NumberFormat;
import java.util.Objects;

public class HealthcareRiskAnalysisApp extends Application {
    private TextField sleField;
    private TextField aroField;

    //UI Components
    private TabPane mainTabPane;

    //Risk Entry Tab Components
    private TextField threatField;
    private ComboBox<HIPAARule> hipaaRuleCombo;
    private ComboBox<RMFStep> rmfStepCombo;
    private TextField impactField;
    private TextField likelihoodField;

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
        scene.getStylesheets().add(Objects.requireNonNull(getClass().getResource("/css/styles.css")).toExternalForm());
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
        sleField = new TextField();  //New field for SLE
        aroField = new TextField();  //New field for ARO
        Button addRiskButton = new Button("Add Risk");

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
        grid.add(new Label("Single Loss Expectancy (SLE):"), 0, 5);
        grid.add(sleField, 1, 5);
        grid.add(new Label("Annualised Rate of Occurrence (ARO):"), 0, 6);
        grid.add(aroField, 1, 6);
        grid.add(addRiskButton, 1, 7);  //Adjusted position of the button

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
            Risk risk = getRisk();

            if (ValidationUtil.isValidRisk(risk)) {
                risks.add(risk);
                clearRiskEntryFields();
                updateAnalysis();
            } else {
                showAlert("Invalid Risk Entry", "Please ensure all fields are filled correctly and values are within acceptable ranges.");
            }
        } catch (NumberFormatException ex) {
            showAlert("Invalid Input", "Please enter valid numbers for impact, likelihood, SLE, and ARO.");
        }
    }

    private Risk getRisk() {
        String threat = threatField.getText();
        HIPAARule hipaaRule = hipaaRuleCombo.getValue();
        RMFStep rmfStep = rmfStepCombo.getValue();
        int impact = Integer.parseInt(impactField.getText());
        int likelihood = Integer.parseInt(likelihoodField.getText());
        double sle = Double.parseDouble(sleField.getText());
        double aro = Double.parseDouble(aroField.getText());

        //Create the Risk object with all required parameters
        return new Risk(threat, hipaaRule, rmfStep, impact, likelihood, sle, aro);
    }

    private void clearRiskEntryFields() {
        threatField.clear();
        hipaaRuleCombo.getSelectionModel().clearSelection();
        rmfStepCombo.getSelectionModel().clearSelection();
        impactField.clear();
        likelihoodField.clear();
        sleField.clear();  //Clear SLE field
        aroField.clear();  //Clear ARO field
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

        TableColumn<Risk, Integer> rpnColumn = new TableColumn<>("RPN");
        rpnColumn.setCellValueFactory(data -> data.getValue().riskPriorityNumberProperty().asObject());

        TableColumn<Risk, String> sleColumn = new TableColumn<>("SLE");
        sleColumn.setCellValueFactory(data -> {
            double sleValue = data.getValue().getSingleLossExpectancy();
            String formattedSLE = NumberFormat.getCurrencyInstance().format(sleValue);
            return new SimpleStringProperty(formattedSLE);
        });

        TableColumn<Risk, Double> aroColumn = new TableColumn<>("ARO");
        aroColumn.setCellValueFactory(data -> data.getValue().annualisedRateOfOccurrenceProperty().asObject());

        TableColumn<Risk, String> aleColumn = new TableColumn<>("ALE");
        aleColumn.setCellValueFactory(data -> {
            double aleValue = data.getValue().getannualisedLossExpectancy();
            String formattedALE = NumberFormat.getCurrencyInstance().format(aleValue);
            return new SimpleStringProperty(formattedALE);
        });
        TableColumn<Risk, String> recommendationColumn = new TableColumn<>("Recommendations");
        recommendationColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().generateRecommendation()));

        riskTable.getColumns().addAll(threatColumn, hipaaRuleColumn, rmfStepColumn, impactColumn, likelihoodColumn, rpnColumn, sleColumn, aroColumn, aleColumn, recommendationColumn);
        riskTable.setItems(risks);
    }


    private void updateAnalysis() {
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
        Categorise, SELECT, IMPLEMENT, ASSESS, Authorise, MONITOR
    }

    public class Risk {
        private final SimpleStringProperty threat;
        private final ObjectProperty<HIPAARule> hipaaRule;
        private final ObjectProperty<RMFStep> rmfStep;
        private final SimpleIntegerProperty impact;
        private final SimpleIntegerProperty likelihood;
        private final SimpleIntegerProperty riskPriorityNumber;

        private SimpleDoubleProperty singleLossExpectancy;          //SLE
        private SimpleDoubleProperty annualisedRateOfOccurrence;    //ARO
        private SimpleDoubleProperty annualisedLossExpectancy;      //ALE = SLE * ARO

        public Risk(String threat, HIPAARule hipaaRule, RMFStep rmfStep, int impact, int likelihood, double singleLossExpectancy, double annualisedRateOfOccurrence) {

            this.threat = new SimpleStringProperty(threat);
            this.hipaaRule = new SimpleObjectProperty<>(hipaaRule);
            this.rmfStep = new SimpleObjectProperty<>(rmfStep);
            this.impact = new SimpleIntegerProperty(impact);
            this.likelihood = new SimpleIntegerProperty(likelihood);
            this.riskPriorityNumber = new SimpleIntegerProperty(impact * likelihood);

            this.singleLossExpectancy = new SimpleDoubleProperty(singleLossExpectancy);
            this.annualisedRateOfOccurrence = new SimpleDoubleProperty(annualisedRateOfOccurrence);
            this.annualisedLossExpectancy = new SimpleDoubleProperty(calculateALE());
        }

        //Getter and Setters
        public String getThreat() {
            return threat.get();
        }

        public void setThreat(String threat) {
            this.threat.set(threat);
        }

        public SimpleStringProperty threatProperty() {
            return threat;
        }

        public HIPAARule getHipaaRule() {
            return hipaaRule.get();
        }

        public void setHipaaRule(HIPAARule hipaaRule) {
            this.hipaaRule.set(hipaaRule);
        }

        public ObjectProperty<HIPAARule> hipaaRuleProperty() {
            return hipaaRule;
        }

        public RMFStep getRmfStep() {
            return rmfStep.get();
        }

        public void setRmfStep(RMFStep rmfStep) {
            this.rmfStep.set(rmfStep);
        }

        public ObjectProperty<RMFStep> rmfStepProperty() {
            return rmfStep;
        }

        public int getImpact() {
            return impact.get();
        }

        public void setImpact(int impact) {
            this.impact.set(impact);
            updateRiskPriorityNumber();
        }

        public SimpleIntegerProperty impactProperty() {
            return impact;
        }

        public int getLikelihood() {
            return likelihood.get();
        }

        public void setLikelihood(int likelihood) {
            this.likelihood.set(likelihood);
            updateRiskPriorityNumber();
        }

        public SimpleIntegerProperty likelihoodProperty() {
            return likelihood;
        }

        public int getRiskPriorityNumber() {
            return riskPriorityNumber.get();
        }

        public SimpleIntegerProperty riskPriorityNumberProperty() {
            return riskPriorityNumber;
        }

        private void updateRiskPriorityNumber() {
            this.riskPriorityNumber.set(getImpact() * getLikelihood());
        }

        public double getSingleLossExpectancy() {
            return singleLossExpectancy.get();
        }

        public void setSingleLossExpectancy(double sle) {
            this.singleLossExpectancy.set(sle);
            updateAnnualisedLossExpectancy();
        }

        public SimpleDoubleProperty singleLossExpectancyProperty() {
            return singleLossExpectancy;
        }

        public double getannualisedRateOfOccurrence() {
            return annualisedRateOfOccurrence.get();
        }

        public void setannualisedRateOfOccurrence(double aro) {
            this.annualisedRateOfOccurrence.set(aro);
            updateAnnualisedLossExpectancy();
        }

        public SimpleDoubleProperty annualisedRateOfOccurrenceProperty() {
            return annualisedRateOfOccurrence;
        }

        public double getannualisedLossExpectancy() {
            return annualisedLossExpectancy.get();
        }

        public SimpleDoubleProperty annualisedLossExpectancyProperty() {
            return annualisedLossExpectancy;
        }

        private double calculateALE() {
            return getSingleLossExpectancy() * getannualisedRateOfOccurrence();
        }

        private void updateAnnualisedLossExpectancy() {
            this.annualisedLossExpectancy.set(calculateALE());
        }

        //Calculate Risk Priority Number (RPN)
        public int calculateRPN() {
            return getImpact() * getLikelihood();
        }

        //Generate recommendations based on risk attributes
        public String generateRecommendation() {
            StringBuilder recommendations = new StringBuilder();
            int rpn = getRiskPriorityNumber();
            double ale = getannualisedLossExpectancy();

            //Provide recommendations based on RPN
            if (rpn > 200) {
                recommendations.append("Critical risk identified. Immediate action required.\n");
            } else if (rpn > 70) {
                recommendations.append("High risk. Prompt attention is necessary.\n");
            } else if (rpn > 20) {
                recommendations.append("Medium risk. Monitor and plan mitigation strategies.\n");
            } else {
                recommendations.append("Low risk. Regular monitoring is sufficient.\n");
            }

            //Provide recommendations based on ALE
            if (ale > 100_000) {
                recommendations.append("ALE exceeds R100,000. Consider investing in significant risk mitigation measures.\n");
            } else if (ale > 50_000) {
                recommendations.append("ALE exceeds R50,000. Evaluate cost-effective mitigation strategies.\n");
            } else {
                recommendations.append("ALE is within acceptable limits. Maintain current controls.\n");
            }

            //Additional recommendations based on impacts
            if (getImpact() > 7) {
                recommendations.append("High impact risk. prioritise impact reduction measures.\n");
            }

            if (getLikelihood() > 7) {
                recommendations.append("High likelihood risk. Implement measures to reduce occurrence.\n");
            }

            //Specific recommendations based on HIPAA Rule
            switch (getHipaaRule()) {
                case PRIVACY_RULE:
                    recommendations.append("Ensure all PHI disclosures are compliant with the Privacy Rule.\n");
                    break;
                case SECURITY_RULE:
                    recommendations.append("Strengthen technical safeguards to protect ePHI.\n");
                    break;
                case BREACH_NOTIFICATION_RULE:
                    recommendations.append("Develop a robust breach response plan in line with notification requirements.\n");
                    break;
            }

            //Specific recommendations based on RMF Step
            switch (getRmfStep()) {
                case Categorise:
                    recommendations.append("Review system categorisations to ensure appropriate risk levels.\n");
                    break;
                case SELECT:
                    recommendations.append("Select security controls tailored to mitigate identified risks.\n");
                    break;
                case IMPLEMENT:
                    recommendations.append("Implement the chosen security controls effectively.\n");
                    break;
                case ASSESS:
                    recommendations.append("Regularly assess the effectiveness of security controls.\n");
                    break;
                case Authorise:
                    recommendations.append("Obtain necessary authorisations before system operation.\n");
                    break;
                case MONITOR:
                    recommendations.append("Continuously monitor security controls and system operations.\n");
                    break;
            }

            return recommendations.toString();
        }
    }

    public static class ValidationUtil {
        public static boolean isValidRisk(Risk risk) {
            return risk != null && risk.getThreat() != null && !risk.getThreat().isEmpty() && risk.getHipaaRule() != null && risk.getRmfStep() != null && risk.getImpact() >= 1 && risk.getImpact() <= 10 && risk.getLikelihood() >= 1 && risk.getLikelihood() <= 10 && risk.getSingleLossExpectancy() >= 0 && risk.getannualisedRateOfOccurrence() >= 0;
        }
    }

    //Chart Utility Class
    public static class ChartUtil {
        public static void updateRiskChart(BarChart<String, Number> chart, List<Risk> risks) {
            XYChart.Series<String, Number> aleSeries = new XYChart.Series<>();
            aleSeries.setName("annualised Loss Expectancy (ALE)");

            for (Risk risk : risks) {
                XYChart.Data<String, Number> dataPoint = new XYChart.Data<>(risk.getThreat(), risk.getannualisedLossExpectancy());
                aleSeries.getData().add(dataPoint);

                double aleValue = risk.getannualisedLossExpectancy();
                String formattedALE = NumberFormat.getCurrencyInstance().format(aleValue);

                Tooltip tooltip = new Tooltip("ALE: " + formattedALE);
                Tooltip.install(dataPoint.getNode(), tooltip);
            }

            chart.getData().clear();
            chart.getData().add(aleSeries);

            // Format the y-axis to display currency
            NumberAxis yAxis = (NumberAxis) chart.getYAxis();
            yAxis.setTickLabelFormatter(new StringConverter<Number>() {
                @Override
                public String toString(Number object) {
                    return NumberFormat.getCurrencyInstance().format(object.doubleValue());
                }

                @Override
                public Number fromString(String string) {
                    // Not needed for display purposes
                    return null;
                }
            });
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}

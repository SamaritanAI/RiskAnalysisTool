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
    private TextField controlMeasuresField;
    private TextField controlEffectivenessField;

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

        //testing
        addPredefinedRisks();
        updateAnalysis();

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

        //Tab for the Bar Chart
        Tab riskChartTab = new Tab("Risk Chart");
        riskChartTab.setContent(createRiskChartContent());
        riskChartTab.setClosable(false);

        mainTabPane.getTabs().addAll(riskEntryTab, riskAnalysisTab, riskChartTab);

    }


    private void addPredefinedRisks() {
        /*risks.add(new Risk("Threat 1", HIPAARule.PRIVACY_RULE, RMFStep.SELECT, 3, 9, 1000000, 0.5, "Yes", 80.0));
        risks.add(new Risk("Threat 2", HIPAARule.SECURITY_RULE, RMFStep.ASSESS, 5, 7, 2000000, 1.0, "This", 60.0));
        risks.add(new Risk("Threat 3", HIPAARule.BREACH_NOTIFICATION_RULE, RMFStep.MONITOR, 8, 8, 500000, 0.8, "Monitor", 75.0));
        risks.add(new Risk("Threat 4", HIPAARule.SECURITY_RULE, RMFStep.IMPLEMENT, 2, 5, 100000, 0.3, "Implement", 50.0));
        risks.add(new Risk("Threat 5", HIPAARule.PRIVACY_RULE, RMFStep.AUTHORISE, 7, 6, 1500000, 0.7, "Authorize", 90.0));*/

        //Test Case 1: High Risk with Effective Controls
        risks.add(new Risk(
                "Unauthorised access to patient data",
                HIPAARule.SECURITY_RULE,
                RMFStep.IMPLEMENT,
                9, 8,
                100000, 0.7,
                "Multi-factor authentication and regular security audits",
                70.0
        ));

        //Test Case 2: Critical Risk with Ineffective Controls
        risks.add(new Risk(
                "Ransomware attack causing system-wide shutdown",
                HIPAARule.SECURITY_RULE,
                RMFStep.SELECT,
                10, 9,
                500000, 0.3,
                "Outdated antivirus software",
                10.0
        ));

        //Test Case 2: Low Risk with No Controls
        risks.add(new Risk(
                "Minor software bugs leading to slight data inconsistencies",
                HIPAARule.PRIVACY_RULE,
                RMFStep.MONITOR,
                2, 3,
                1000, 0.2,
                "None",
                0.0
        ));

        //Test Case 3: Medium Risk with Partial Controls
        risks.add(new Risk(
                "Phishing attacks targeting staff emails",
                HIPAARule.BREACH_NOTIFICATION_RULE,
                RMFStep.ASSESS,
                6, 5,
                10000, 1.5,
                "Basic cybersecurity training for staff",
                40.0
        ));

    }

    private Parent createRiskEntryContent() {
        threatField = new TextField();
        hipaaRuleCombo = new ComboBox<>();
        rmfStepCombo = new ComboBox<>();
        impactField = new TextField();
        likelihoodField = new TextField();
        sleField = new TextField();
        aroField = new TextField();
        controlMeasuresField = new TextField();
        controlEffectivenessField = new TextField();
        Button addRiskButton = new Button("Add Risk");

        hipaaRuleCombo.getItems().setAll(HIPAARule.values());
        rmfStepCombo.getItems().setAll(RMFStep.values());

        controlMeasuresField.setPromptText("Describe existing controls");
        controlEffectivenessField.setPromptText("Enter effectiveness (0-100)");

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
        grid.add(new Label("Control Measures:"), 0, 7);
        grid.add(controlMeasuresField, 1, 7);
        grid.add(new Label("Control Effectiveness (%):"), 0, 8);
        grid.add(controlEffectivenessField, 1, 8);
        grid.add(addRiskButton, 1, 9);

        addRiskButton.setOnAction(e -> handleAddRisk());

        return grid;
    }

    private Parent createRiskChartContent() {
        riskChart = new BarChart<>(new CategoryAxis(), new NumberAxis());

        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(20));
        vbox.getChildren().add(riskChart);

        updateAnalysis();

        return vbox;
    }



    private Parent createRiskAnalysisContent() {
        riskTable = new TableView<>();
        setupRiskTable();

        GridPane riskMatrix = createRiskMatrix();

        //Listener to riskTable to highlight the matrix cell corresponding to the selected risk
        riskTable.getSelectionModel().selectedItemProperty().addListener((obs, oldSelection, newSelection) -> {
            if (newSelection != null) {
                highlightMatrixCell(newSelection.getImpact(), newSelection.getLikelihood());
            }
        });

        VBox vbox = new VBox(10);
        vbox.setPadding(new Insets(20));
        vbox.getChildren().addAll(riskTable, riskMatrix);

        return vbox;
    }



    private void highlightMatrixCell(int impact, int likelihood) {
        clearMatrixHighlights();

        Label selectedCell = riskMatrixLabels[likelihood - 1][impact - 1];
        selectedCell.setStyle("-fx-border-color: black; -fx-border-width: 2px; -fx-background-color: lightblue;");
    }

    private void clearMatrixHighlights() {
        for (int i = 0; i < 10; i++) {
            for (int j = 0; j < 10; j++) {
                riskMatrixLabels[i][j].setStyle("");
            }
        }
    }

    //2D array to store matrix labels for highlighting
    private Label[][] riskMatrixLabels = new Label[10][10];

    private GridPane createRiskMatrix() {
        GridPane matrix = new GridPane();
        matrix.setPadding(new Insets(20));
        matrix.setHgap(10);
        matrix.setVgap(10);

        for (int i = 1; i <= 10; i++) {
            matrix.add(new Label("Impact " + i), i, 0);
            matrix.add(new Label("Likelihood " + i), 0, i);
        }

        //Matrix with categories (Low, Medium, High, Critical)
        for (int i = 1; i <= 10; i++) {
            for (int j = 1; j <= 10; j++) {
                final int impact = i;
                final int likelihood = j;

                String category = categorizeRisk(impact, likelihood);  //Determine risk category based on impact and likelihood
                Label riskLabel = new Label(category);

                switch (category) {
                    case "Critical":
                        riskLabel.getStyleClass().add("critical-risk");
                        break;
                    case "High":
                        riskLabel.getStyleClass().add("high-risk");
                        break;
                    case "Medium":
                        riskLabel.getStyleClass().add("medium-risk");
                        break;
                    case "Low":
                        riskLabel.getStyleClass().add("low-risk");
                        break;
                }

                riskMatrixLabels[likelihood - 1][impact - 1] = riskLabel;

                matrix.add(riskLabel, i, j);
            }
        }

        return matrix;
    }



    private String categorizeRisk(int impact, int likelihood) {
        int rpn = impact * likelihood;
        if (rpn > 200) {
            return "Critical";
        } else if (rpn > 70) {
            return "High";
        } else if (rpn > 20) {
            return "Medium";
        } else {
            return "Low";
        }
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
        String controlMeasures = controlMeasuresField.getText();
        double controlEffectiveness = Double.parseDouble(controlEffectivenessField.getText());

        return new Risk(threat, hipaaRule, rmfStep, impact, likelihood, sle, aro, controlMeasures, controlEffectiveness);
    }

    private void clearRiskEntryFields() {
        threatField.clear();
        hipaaRuleCombo.getSelectionModel().clearSelection();
        rmfStepCombo.getSelectionModel().clearSelection();
        impactField.clear();
        likelihoodField.clear();
        sleField.clear();
        aroField.clear();
        controlMeasuresField.clear();
        controlEffectivenessField.clear();
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
            double aleValue = data.getValue().getAnnualisedLossExpectancy();
            String formattedALE = NumberFormat.getCurrencyInstance().format(aleValue);
            return new SimpleStringProperty(formattedALE);
        });

        TableColumn<Risk, String> controlMeasuresColumn = new TableColumn<>("Control Measures");
        controlMeasuresColumn.setCellValueFactory(data -> data.getValue().controlMeasuresProperty());

        TableColumn<Risk, Double> controlEffectivenessColumn = new TableColumn<>("Control Effectiveness (%)");
        controlEffectivenessColumn.setCellValueFactory(data -> data.getValue().controlEffectivenessProperty().asObject());

        TableColumn<Risk, String> recommendationColumn = new TableColumn<>("Recommendations");
        recommendationColumn.setCellValueFactory(data -> new SimpleStringProperty(data.getValue().generateRecommendation()));

        TableColumn<Risk, Double> residualRiskColumn = new TableColumn<>("Residual Risk");
        residualRiskColumn.setCellValueFactory(data -> data.getValue().residualRiskProperty().asObject());

        riskTable.getColumns().addAll(threatColumn, hipaaRuleColumn, rmfStepColumn, impactColumn, likelihoodColumn, rpnColumn, residualRiskColumn, sleColumn, aroColumn, aleColumn, controlMeasuresColumn, controlEffectivenessColumn, recommendationColumn);
        riskTable.setItems(risks);
    }

        private void updateAnalysis() {
        riskChart.getData().clear();

        if (risks.isEmpty()) {
            return;
        }

        XYChart.Series<String, Number> aleSeries = new XYChart.Series<>();
        aleSeries.setName("Annualised Loss Expectancy (ALE)");

        for (Risk risk : risks) {
            XYChart.Data<String, Number> dataPoint = new XYChart.Data<>(risk.getThreat(), risk.getAnnualisedLossExpectancy());
            aleSeries.getData().add(dataPoint);

            String formattedALE = NumberFormat.getCurrencyInstance().format(risk.getAnnualisedLossExpectancy());
            Tooltip tooltip = new Tooltip("ALE: " + formattedALE);
            Tooltip.install(dataPoint.getNode(), tooltip);
        }

        riskChart.getData().add(aleSeries);

        NumberAxis yAxis = (NumberAxis) riskChart.getYAxis();
        yAxis.setTickLabelFormatter(new StringConverter<Number>() {
            @Override
            public String toString(Number object) {
                return NumberFormat.getCurrencyInstance().format(object.doubleValue());
            }

            @Override
            public Number fromString(String string) {
                return null;
            }
        });
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
        Categorise, SELECT, IMPLEMENT, ASSESS, Authorise, AUTHORISE, MONITOR
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

        private final SimpleStringProperty controlMeasures;
        private final SimpleDoubleProperty controlEffectiveness;
        private final SimpleDoubleProperty residualRisk;


        public Risk(String threat, HIPAARule hipaaRule, RMFStep rmfStep, int impact, int likelihood, double singleLossExpectancy, double annualisedRateOfOccurrence, String controlMeasures, double controlEffectiveness) {

            this.threat = new SimpleStringProperty(threat);
            this.hipaaRule = new SimpleObjectProperty<>(hipaaRule);
            this.rmfStep = new SimpleObjectProperty<>(rmfStep);
            this.impact = new SimpleIntegerProperty(impact);
            this.likelihood = new SimpleIntegerProperty(likelihood);
            this.riskPriorityNumber = new SimpleIntegerProperty(impact * likelihood);

            this.singleLossExpectancy = new SimpleDoubleProperty(singleLossExpectancy);
            this.annualisedRateOfOccurrence = new SimpleDoubleProperty(annualisedRateOfOccurrence);
            this.annualisedLossExpectancy = new SimpleDoubleProperty(calculateALE());

            this.controlMeasures = new SimpleStringProperty(controlMeasures);
            this.controlEffectiveness = new SimpleDoubleProperty(controlEffectiveness);
            this.residualRisk = new SimpleDoubleProperty(calculateResidualRisk());
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

        public void setAnnualisedRateOfOccurrence(double aro) {
            this.annualisedRateOfOccurrence.set(aro);
            updateAnnualisedLossExpectancy();
        }

        public SimpleDoubleProperty annualisedRateOfOccurrenceProperty() {
            return annualisedRateOfOccurrence;
        }

        public double getAnnualisedLossExpectancy() {
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

        //Control Measures
        public String getControlMeasures() {
            return controlMeasures.get();
        }

        public void setControlMeasures(String controlMeasures) {
            this.controlMeasures.set(controlMeasures);
        }

        public SimpleStringProperty controlMeasuresProperty() {
            return controlMeasures;
        }

        //Control Effectiveness
        public double getControlEffectiveness() {
            return controlEffectiveness.get();
        }

        public void setControlEffectiveness(double controlEffectiveness) {
            this.controlEffectiveness.set(controlEffectiveness);
            updateResidualRisk();
        }

        public SimpleDoubleProperty controlEffectivenessProperty() {
            return controlEffectiveness;
        }

        //Residual Risk
        public double getResidualRisk() {
            return residualRisk.get();
        }

        public SimpleDoubleProperty residualRiskProperty() {
            return residualRisk;
        }

        private double calculateResidualRisk() {
            double effectiveness = getControlEffectiveness() / 100.0; //Convert to decimal
            return getRiskPriorityNumber() * (1 - effectiveness);
        }

        private void updateResidualRisk() {
            this.residualRisk.set(calculateResidualRisk());
        }

        //Calculate Risk Priority Number (RPN)
        public int calculateRPN() {
            return getImpact() * getLikelihood();
        }

        //Generate recommendations based on risk attributes
        public String generateRecommendation() {
            StringBuilder recommendations = new StringBuilder();
            int rpn = getRiskPriorityNumber();
            double ale = getAnnualisedLossExpectancy();
            double residual = getResidualRisk();

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

            //Recommendations based on impacts
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
            boolean baseValidation = risk != null && risk.getThreat() != null && !risk.getThreat().isEmpty() && risk.getHipaaRule() != null && risk.getRmfStep() != null && risk.getImpact() >= 1 && risk.getImpact() <= 10 && risk.getLikelihood() >= 1 && risk.getLikelihood() <= 10 && risk.getSingleLossExpectancy() >= 0 && risk.getannualisedRateOfOccurrence() >= 0;

            boolean controlValidation = risk.getControlEffectiveness() >= 0 && risk.getControlEffectiveness() <= 100;

            return baseValidation && controlValidation;
        }
    }

    public static class ChartUtil {
        public static void updateRiskChart(BarChart<String, Number> chart, List<Risk> risks) {
            XYChart.Series<String, Number> aleSeries = new XYChart.Series<>();
            aleSeries.setName("Annualised Loss Expectancy (ALE)");

            for (Risk risk : risks) {
                XYChart.Data<String, Number> dataPoint = new XYChart.Data<>(risk.getThreat(), risk.getAnnualisedLossExpectancy());
                aleSeries.getData().add(dataPoint);

                double aleValue = risk.getAnnualisedLossExpectancy();
                String formattedALE = NumberFormat.getCurrencyInstance().format(aleValue);

                Tooltip tooltip = new Tooltip("ALE: " + formattedALE);
                Tooltip.install(dataPoint.getNode(), tooltip);
            }

            chart.getData().clear();
            chart.getData().add(aleSeries);

            //Format the y-axis to display currency
            NumberAxis yAxis = (NumberAxis) chart.getYAxis();
            yAxis.setTickLabelFormatter(new StringConverter<Number>() {
                @Override
                public String toString(Number object) {
                    return NumberFormat.getCurrencyInstance().format(object.doubleValue());
                }

                @Override
                public Number fromString(String string) {
                    return null;
                }
            });
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}

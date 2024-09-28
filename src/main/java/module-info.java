module com.infosec.riskanalysistool {
    requires javafx.controls;
    requires javafx.fxml;

    requires org.controlsfx.controls;
    requires com.dlsc.formsfx;
    requires net.synedra.validatorfx;
    requires org.kordamp.bootstrapfx.core;

    // This opens the controller package for reflection access by JavaFX

    // Exporting packages if needed by other modules
    exports com.infosec.riskanalysistool;
}
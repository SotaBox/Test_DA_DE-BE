# AI Engineer position skill test. EDA and XGBoost for Equipment Failure Prediction
## Part 1: Exploratory Data Analysis (EDA)
    1. Load the dataset and display basic information (rows, columns, data types).
    2. Show the distribution of the target variable (failure_last).
    3. Create a correlation heatmap for numerical features.
    4. Identify the top 3 features most correlated with failure_last.
## Part 2: XGBoost Model 
    1. Prepare the data:
        - Handle any missing values.
        - Encode categorical variables if necessary.
        - Split data into 80% training and 20% testing sets.
    2.Train an XGBoost model:
        - Use default parameters.
        - Predict on the test set.
    3. Evaluate the model:
        - Calculate and report accuracy, precision, recall, and F1-score.
        - Plot the ROC curve and report the AUC score.
    4. Feature Importance:
        - Plot the top 5 most important features.
        - Briefly explain their significance for predicting equipment failure.
## Bonus (if time permits):
Implement one technique to improve the model's performance (e.g., handle class imbalance or basic hyperparameter tuning).
Note: Provide concise comments in your code to explain your approach.
Total time: 60 minutes
Version 3 of 3


"""
PhishCatcher Model Training
Train logistic regression model on phishing dataset
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
import pickle
import os
import warnings
warnings.filterwarnings('ignore')

class PhishingModelTrainer:
    """Train and evaluate phishing detection model"""
    
    def __init__(self):
        self.model = None
        self.X_train = None
        self.X_test = None
        self.y_train = None
        self.y_test = None
        
    def create_sample_dataset(self, n_samples=1000):
        """
        Create a sample phishing dataset for demonstration
        In production, replace with real phishing dataset
        """
        print("Creating sample dataset...")
        
        np.random.seed(42)
        
        # Generate synthetic phishing and legitimate samples
        phishing_samples = n_samples // 2
        legitimate_samples = n_samples - phishing_samples
        
        # Phishing characteristics (tend to be higher/more suspicious)
        phishing_data = {
            'url_length': np.random.randint(60, 250, phishing_samples),
            'has_at_symbol': np.random.choice([0, 1], phishing_samples, p=[0.3, 0.7]),
            'num_dots': np.random.randint(3, 15, phishing_samples),
            'is_https': np.random.choice([0, 1], phishing_samples, p=[0.6, 0.4]),
            'num_hyphens': np.random.randint(2, 10, phishing_samples),
            'has_ip_address': np.random.choice([0, 1], phishing_samples, p=[0.4, 0.6]),
            'num_suspicious_keywords': np.random.randint(1, 5, phishing_samples),
            'num_input_fields': np.random.randint(3, 20, phishing_samples),
            'has_password_field': np.random.choice([0, 1], phishing_samples, p=[0.2, 0.8]),
            'form_action_mismatch': np.random.choice([0, 1], phishing_samples, p=[0.3, 0.7]),
            'num_external_links': np.random.randint(5, 30, phishing_samples),
            'has_hidden_fields': np.random.choice([0, 1], phishing_samples, p=[0.4, 0.6]),
            'num_iframes': np.random.randint(0, 5, phishing_samples),
            'url_entropy': np.random.uniform(3.5, 5.0, phishing_samples),
            'domain_age_days': np.random.randint(0, 180, phishing_samples),
            'label': np.ones(phishing_samples)  # 1 = phishing
        }
        
        # Legitimate characteristics (tend to be lower/less suspicious)
        legitimate_data = {
            'url_length': np.random.randint(20, 80, legitimate_samples),
            'has_at_symbol': np.random.choice([0, 1], legitimate_samples, p=[0.9, 0.1]),
            'num_dots': np.random.randint(1, 4, legitimate_samples),
            'is_https': np.random.choice([0, 1], legitimate_samples, p=[0.2, 0.8]),
            'num_hyphens': np.random.randint(0, 3, legitimate_samples),
            'has_ip_address': np.random.choice([0, 1], legitimate_samples, p=[0.95, 0.05]),
            'num_suspicious_keywords': np.random.randint(0, 2, legitimate_samples),
            'num_input_fields': np.random.randint(0, 8, legitimate_samples),
            'has_password_field': np.random.choice([0, 1], legitimate_samples, p=[0.5, 0.5]),
            'form_action_mismatch': np.random.choice([0, 1], legitimate_samples, p=[0.9, 0.1]),
            'num_external_links': np.random.randint(0, 10, legitimate_samples),
            'has_hidden_fields': np.random.choice([0, 1], legitimate_samples, p=[0.8, 0.2]),
            'num_iframes': np.random.randint(0, 2, legitimate_samples),
            'url_entropy': np.random.uniform(2.0, 3.5, legitimate_samples),
            'domain_age_days': np.random.randint(180, 3650, legitimate_samples),
            'label': np.zeros(legitimate_samples)  # 0 = legitimate
        }
        
        # Combine datasets
        phishing_df = pd.DataFrame(phishing_data)
        legitimate_df = pd.DataFrame(legitimate_data)
        df = pd.concat([phishing_df, legitimate_df], ignore_index=True)
        
        # Shuffle
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # Save dataset
        df.to_csv('phishing_dataset.csv', index=False)
        print(f"✓ Dataset created: {len(df)} samples")
        print(f"  - Phishing: {phishing_samples}")
        print(f"  - Legitimate: {legitimate_samples}")
        
        return df
    
    def load_dataset(self, filepath='phishing_dataset.csv'):
        """Load dataset from CSV file"""
        try:
            if os.path.exists(filepath):
                df = pd.read_csv(filepath)
                print(f"✓ Dataset loaded: {len(df)} samples")
                return df
            else:
                print("Dataset not found. Creating sample dataset...")
                return self.create_sample_dataset()
        except Exception as e:
            print(f"Error loading dataset: {e}")
            print("Creating sample dataset...")
            return self.create_sample_dataset()
    
    def prepare_data(self, df):
        """Split dataset into features and labels"""
        print("\nPreparing data...")
        
        # Separate features and labels
        X = df.drop('label', axis=1)
        y = df['label']
        
        # Split into train and test sets
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"✓ Training samples: {len(self.X_train)}")
        print(f"✓ Testing samples: {len(self.X_test)}")
        
        return self.X_train, self.X_test, self.y_train, self.y_test
    
    def train_model(self):
        """Train logistic regression model"""
        print("\nTraining model...")
        
        self.model = LogisticRegression(
            max_iter=1000,
            random_state=42,
            solver='lbfgs'
        )
        
        self.model.fit(self.X_train, self.y_train)
        print("✓ Model trained successfully")
        
        return self.model
    
    def evaluate_model(self):
        """Evaluate model performance"""
        print("\n" + "="*60)
        print("MODEL EVALUATION")
        print("="*60)
        
        # Predictions
        y_pred_train = self.model.predict(self.X_train)
        y_pred_test = self.model.predict(self.X_test)
        
        # Training metrics
        train_accuracy = accuracy_score(self.y_train, y_pred_train)
        print(f"\n📊 Training Accuracy: {train_accuracy:.4f}")
        
        # Testing metrics
        test_accuracy = accuracy_score(self.y_test, y_pred_test)
        test_precision = precision_score(self.y_test, y_pred_test)
        test_recall = recall_score(self.y_test, y_pred_test)
        test_f1 = f1_score(self.y_test, y_pred_test)
        
        print(f"\n📊 Testing Metrics:")
        print(f"  Accuracy:  {test_accuracy:.4f}")
        print(f"  Precision: {test_precision:.4f}")
        print(f"  Recall:    {test_recall:.4f}")
        print(f"  F1-Score:  {test_f1:.4f}")
        
        # Confusion Matrix
        cm = confusion_matrix(self.y_test, y_pred_test)
        print(f"\n📊 Confusion Matrix:")
        print(f"                Predicted")
        print(f"              Legit  Phish")
        print(f"  Actual Legit  {cm[0][0]:4d}   {cm[0][1]:4d}")
        print(f"         Phish  {cm[1][0]:4d}   {cm[1][1]:4d}")
        
        # Classification Report
        print(f"\n📊 Detailed Classification Report:")
        print(classification_report(
            self.y_test, y_pred_test,
            target_names=['Legitimate', 'Phishing']
        ))
        
        return {
            'accuracy': test_accuracy,
            'precision': test_precision,
            'recall': test_recall,
            'f1_score': test_f1
        }
    
    def save_model(self, filepath='phishing_model.pkl'):
        """Save trained model to disk"""
        with open(filepath, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"\n✓ Model saved to: {filepath}")
    
    def get_feature_importance(self):
        """Display feature importance"""
        feature_names = [
            'url_length', 'has_at_symbol', 'num_dots', 'is_https',
            'num_hyphens', 'has_ip_address', 'num_suspicious_keywords',
            'num_input_fields', 'has_password_field', 'form_action_mismatch',
            'num_external_links', 'has_hidden_fields', 'num_iframes',
            'url_entropy', 'domain_age_days'
        ]
        
        coefficients = self.model.coef_[0]
        importance_df = pd.DataFrame({
            'Feature': feature_names,
            'Coefficient': coefficients,
            'Abs_Coefficient': np.abs(coefficients)
        }).sort_values('Abs_Coefficient', ascending=False)
        
        print("\n📊 Feature Importance (Top 10):")
        print("="*60)
        for idx, row in importance_df.head(10).iterrows():
            print(f"  {row['Feature']:25s} {row['Coefficient']:8.4f}")
        
        return importance_df

def main():
    """Main training pipeline"""
    print("\n" + "="*60)
    print("  PHISHCATCHER MODEL TRAINING")
    print("="*60 + "\n")
    
    # Initialize trainer
    trainer = PhishingModelTrainer()
    
    # Load or create dataset
    df = trainer.load_dataset()
    
    # Prepare data
    trainer.prepare_data(df)
    
    # Train model
    trainer.train_model()
    
    # Evaluate model
    metrics = trainer.evaluate_model()
    
    # Feature importance
    trainer.get_feature_importance()
    
    # Save model
    trainer.save_model()
    
    print("\n" + "="*60)
    print("✓ TRAINING COMPLETE!")
    print("="*60)
    print("\nNext steps:")
    print("  1. Run: python app.py")
    print("  2. Test API: curl http://localhost:5000/health")
    print("  3. Install Chrome Extension")
    print("="*60 + "\n")

if __name__ == '__main__':
    main()
# \# AI-Based Phishing Email Detection System

# 

# \## Project Overview

# 

# The AI-Based Phishing Email Detection System is a machine learning-based cybersecurity application developed to classify email messages as either phishing or legitimate.

# 

# The system applies Natural Language Processing (NLP) techniques to transform email text into numerical features using Term Frequency-Inverse Document Frequency (TF-IDF). Three machine learning algorithms are evaluated:

# 

# \- Naive Bayes

# \- Logistic Regression

# \- Random Forest

# 

# The experimental results show that Random Forest achieved the best overall performance and was selected as the final classification model.

# 

# The selected model was integrated into a desktop application that allows users to enter an email message and receive an automated classification result.

# 

# \---

# 

# \## Project Aim

# 

# The aim of this project is to design and develop an AI-based system capable of automatically classifying email messages as phishing or legitimate using Natural Language Processing and machine learning techniques.

# 

# \---

# 

# \## Main Objectives

# 

# \- Prepare a labelled email dataset for machine learning.

# \- Preprocess textual email data.

# \- Extract text features using TF-IDF.

# \- Implement multiple machine learning classification algorithms.

# \- Compare model performance using standard evaluation metrics.

# \- Select the best-performing model.

# \- Save the trained model and TF-IDF vectorizer.

# \- Develop a desktop-based phishing email detection application.

# \- Test the system using phishing and legitimate email examples.

# 

# \---

# 

# \## System Architecture

# 

# ```text

# Email Dataset

# &#x20;     |

# &#x20;     v

# Text Preprocessing

# &#x20;     |

# &#x20;     v

# TF-IDF Feature Extraction

# &#x20;     |

# &#x20;     v

# Machine Learning Models

# &#x20;     |

# &#x20;     +------------------+

# &#x20;     |                  |

# &#x20;     v                  v

# Naive Bayes       Logistic Regression

# &#x20;     |                  |

# &#x20;     +--------+---------+

# &#x20;              |

# &#x20;              v

# &#x20;       Random Forest

# &#x20;              |

# &#x20;              v

# &#x20;      Model Evaluation

# &#x20;              |

# &#x20;              v

# &#x20;       Best Model Selected

# &#x20;              |

# &#x20;              v

# &#x20;      Desktop Application

# &#x20;              |

# &#x20;              v

# &#x20;    Phishing / Legitimate


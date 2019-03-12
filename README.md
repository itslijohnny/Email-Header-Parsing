# Email-Header-Parsing

## Background

Spam email is still a common attack method. Most of the email services have spam filters that can help us block and filter out most of the emails with commercial, fraudulent and malicious content. The purpose of the project is to explore the difference between the features of commercial email and malicious email.

## Get Email Header information

This part of the script is to get emails' header for further analysis.
The script uses ```imaplib``` library to get email headers from a Gmail account Spam folder. For the script to work, Gmail IMAP Access need to be enabled. To enable IMAP for Gmail, please check this [instruction](https://support.google.com/mail/answer/7126229). You also need to either turn off 2-Step Verification for your Google account or set up an app password [here](https://myaccount.google.com/u/1/security).

### Setup connection

For this part of the script, I used **Python**
1. Import the required libraries.

```python
import getpass
import imaplib
import email
from email.parser import HeaderParser
from email.header import decode_header
import re
import csv
import pandas as pd
from bs4 import BeautifulSoup
import requests
import json
```

2. Login to the Gmail

```python
print('Email:')
un = input()
print('Password')
pw = getpass.getpass()
conn = imaplib.IMAP4_SSL(port = '993',host = 'imap.gmail.com')
conn.login(un,pw)
```
### Download Email and Parsing Email Header

1. Download email headers and add attributes.

```python
#conn.select('[Gmail]/Index')
conn.select('[Gmail]/Spam')
type, emaildata = conn.search(None, 'ALL')
emaillist=emaildata[0].split()
parser = HeaderParser()
header_list=[]
msg_text=[]
key_f=open("key.txt","r")
key=key_f.readlines()[0]
for a in emaillist:
    type, emaildata2 = conn.fetch(a, '(RFC822)')
    h = parser.parsestr(emaildata2[0][1].decode('utf-8','ignore'))
    for txt in h.walk():
        if not txt.is_multipart():
            msg_text = txt.get_payload(decode=True).decode('utf-8','ignore')
    soup = BeautifulSoup(msg_text, "lxml")
    msg_text= soup.get_text(strip=True)
    header = {}
    header['Subject']=decode_header(h['Subject'])[0][0]
    header['ARC-Authentication-Results']=h['ARC-Authentication-Results'].strip()
    header['Return-Path']=h['Return-Path'].strip()
    header['Return-Path Address']=re.findall(r'\b@\S*\b', str(h['Return-Path'].strip()))[0]
    header['Received']=h['Received'].strip()
    header['Received-SPF']=h['Received-SPF'].strip()
    header['Date']=pd.to_datetime(h['Date'].strip())
    if 'Reply-To' in h:
        header['Reply-To']=h['Reply-To'].strip()
        header['Reply-To Address']=re.findall(r'\b@\S*\b', str(h['Reply-To'].strip()))[0]
    else:
        header['Reply-To']=''
        header['Reply-To Address']=''
    header['Content-Type']=h['Content-Type'].strip().split(';')[0]
    header['From']=h['From'].strip()
    if re.findall(r'\b@\S*\b',str(h['From'].strip())):
        header['From Address']=re.findall(r'\b@\S*\b',str(h['From'].strip()))[0]
    else:
        header['From Address']=''
    #header['Sender-ip']= re.findall(r'(?:(?:25[0-5]|2[0-4]\d|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)',str(header))
    header['Message']= len(msg_text)
    if re.findall(r'\bip=\S*\b',str(header)):
        header['IP']=re.findall(r'\bip=\S*\b',str(header))[0].split('=')[1]
    else:
        header['IP']=''
    if re.findall(r'\bspf=\S*\b',str(header)):
        header['SPF']=re.findall(r'\bspf=\S*\b',str(header))[0].split('=')[1]
    else:
        header['SPF']=''
    if re.findall(r'\bdmarc=\S*\b',str(header)):
        header['DMARC']=re.findall(r'\bdmarc=\S*\b',str(header))[0].split('=')[1]
    else:
        header['DMARC']=''
    if re.findall(r'\bdkim=\S*\b',str(header)):
        header['DKIM']=re.findall(r'\bdkim=\S*\b',str(header))[0].split('=')[1]
    else:
        header['DKIM']=''

    address = "http://api.ipstack.com/"+header['IP']+"?access_key="+key    
    response = requests.get(address)
    ipjason = response.text
    iplist = json.loads(ipjason)
    header['Country']= iplist.get('country_name')
    header['Regin']= iplist.get('region_name')
    header['City']= iplist.get('city')
    if iplist.get('type')== 'ipv6' :
        header['IPv6 Indicator']= 1
    elif iplist.get('type')== 'ipv4' :
        header['IPv6 Indicator']= 0
    header_list.append(header)
```

2. Write the data into csv file.
For consistent analysis, I save the dataframe into a CSV file for further analysis.
```python
keys = header_list[0].keys()
print('File Name:')
fn = input()
with open(fn+'.csv', 'w') as output_file:
    dict_writer = csv.DictWriter(output_file, keys)
    dict_writer.writeheader()
    dict_writer.writerows(header_list)
```

## Data Explortion

### Import the data to R
For this part of the script, I used **R language**  to explore the data and the build model. Therefore We need to import CSV to R first.

```R
em <- read.csv("gamilspamedited.csv",stringsAsFactors = F)
```


    'data.frame':	272 obs. of  18 variables:
     $ Subject            : chr  
     $ Return.Path.Address: chr  
     $ Date               : chr  
     $ Reply.To.Address   : chr
     $ Content.Type       : chr  
     $ From.Address       : chr
     $ IP                 : chr  
     $ SPF                : chr  
     $ DMARC              : chr  
     $ DKIM               : chr
     $ Country            : chr  
     $ Regin              : chr  
     $ City               : chr  
     $ IPv6.Indicator     : int  
     $ CAT                : chr  
     $ Reputation         : chr  

After cleaning the data, there are 272 entries and 18 columns left.

### Preprocess the date

#### Create Variables

##### Email Content

```R
library(dplyr
       )
hashtml.func <- function(x,c1){
    x <- case_when(x[c1]=="multipart/alternative" ~ "1",x[c1]=="multipart/mixed" ~ "1",x[c1]=="multipart/related" ~ "1",x[c1]=="text/html" ~ "1",x[c1]=="text/plain" ~ "0")
}
em$hashtml <- apply(em,1,hashtml.func,c1='Content.Type')
hasattach.func <- function(x,c1){
    x <- case_when(x[c1]=="multipart/alternative" ~ "0",x[c1]=="multipart/mixed" ~ "1",x[c1]=="multipart/related" ~ "0",x[c1]=="text/html" ~ "0",x[c1]=="text/plain" ~ "0")
}
em$hasattach <- apply(em,1,hasattach.func,c1='Content.Type')
```

##### Compare Email Address

```R
library(stringr)
rpavsfrom.func <- function(x){
    fa<-x['From.Address']
    fa<-str_split(fa,'@')[[1]][2]
    fasplit <-str_split(fa,'[.]')[[1]]
    fareal <- paste(str_split(fa,'[.]')[[1]][(length(fasplit)-1)],'.',str_split(fa,'[.]')[[1]][(length(fasplit))],sep = "")
    rp<-x['Return.Path.Address']
    rp<-str_split(rp,'@')[[1]][2]
    rpsplit <-str_split(rp,'[.]')[[1]]
    rpreal <- paste(str_split(rp,'[.]')[[1]][(length(rpsplit)-1)],'.',str_split(rp,'[.]')[[1]][(length(rpsplit))],sep = "")
    if (fareal == rpreal) {
        x = 1
    }else{
        x = 0
    }
    return(x)
}
em$rpavsfrom<-apply(em,1,rpavsfrom.func)
```

```R
library(stringr)
replyvsfrom.func <- function(x){
    fa<-x['From.Address']
    fa<-str_split(fa,'@')[[1]][2]
    fasplit <-str_split(fa,'[.]')[[1]]
    fareal <- paste(str_split(fa,'[.]')[[1]][(length(fasplit)-1)],'.',str_split(fa,'[.]')[[1]][(length(fasplit))],sep = "")
    ra<-x['Reply.To.Address']
    ra<-str_split(ra,'@')[[1]][2]
    rasplit <-str_split(ra,'[.]')[[1]]
    rareal <- paste(str_split(ra,'[.]')[[1]][(length(rasplit)-1)],'.',str_split(ra,'[.]')[[1]][(length(rasplit))],sep = "")
    if (fareal == rareal) {
        x = 1
    }else{
        x = 0
    }
    return(x)
}
em$replyvsfrom<-apply(em,1,replyvsfrom.func)
```

##### Bin and Categorize the Time and the Day

```R
library(lubridate)
weekday.func <- function(x,c1){
    weekday <- wday(as.Date(str_split(x[c1],' ')[[1]][1],format='%m/%d/%Y'))
    return(weekday)
}
em$Weekday <- apply(em,1,weekday.func,c1='Date')
em$Weekday <- factor(em$Weekday)
levels(em$Weekday) <- c("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
```


```R
time.func <- function(x,c1){
    time <- gsub(":", "", str_split(x[c1],' ')[[1]][2])
    return(time)
}
em$Time <- apply(em,1,time.func,c1='Date')
em$Time <- factor(round(as.numeric(em$Time)/100))
```

##### Convert the data to proper format


```R
em$SPF <- factor(em$SPF,levels = c("pass","neutral","fail","temperror"))
em$DMARC <- factor(em$DMARC,levels = c("pass","fail","None"))
em$DKIM <- factor(em$DKIM,levels = c("pass","None"))
em$Country <- factor(em$Country)
em$IPv6.Indicator<-factor(em$IPv6.Indicator)
em$CAT <- factor(em$CAT)
em$Reputation <- factor(em$Reputation)
em$hashtml <- factor(em$hashtml)
em$hasattach <- factor(em$hasattach)
em$rpavsfrom <- factor(em$rpavsfrom)
em$replyvsfrom <- factor(em$replyvsfrom)
```

##### Set base level


```R
em$Country <- relevel(em$Country,ref = "US")
em$Reputation <- relevel(em$Reputation,ref = "Unsuspicious")
```

##### Re-code the target to numeric


```R
em$CAT <- as.numeric(em$CAT == "Spam")
```

### Explore the Relationship


```R
set.seed(11)
selected.var <- c(7, 9, 10, 11, 12, 15, 16,17,18,19,20,21,22,23,24)
selected.df <- em[, selected.var]
```


```R
emnum<-selected.df
levels(selected.df$SPF) <- c("1", "2", "3", "4")
emnum$SPF <- as.numeric(selected.df$SPF)
levels(selected.df$DMARC) <- c("1", "2", "3")
emnum$DMARC <- as.numeric(selected.df$DMARC)
levels(selected.df$DKIM) <- c("1", "2")
emnum$DKIM <- as.numeric(selected.df$DKIM)
levels(selected.df$Country) <- c("1", "2")
emnum$Country <- as.numeric(selected.df$Country)
levels(selected.df$IPv6.Indicator) <- c("1", "2")
emnum$IPv6.Indicator <- as.numeric(selected.df$IPv6.Indicator)
levels(selected.df$Reputation) <- c("1", "2")
emnum$Reputation <- as.numeric(selected.df$Reputation)
levels(selected.df$hashtml) <- c("1", "2")
emnum$hashtml <- as.numeric(selected.df$hashtml)
levels(selected.df$hasattach) <- c("1", "2")
emnum$hasattach <- as.numeric(selected.df$hasattach)
levels(selected.df$rpavsfrom) <- c("1", "2")
emnum$rpavsfrom <- as.numeric(selected.df$rpavsfrom)
levels(selected.df$replyvsfrom) <- c("1", "2")
emnum$replyvsfrom <- as.numeric(selected.df$replyvsfrom)
levels(selected.df$Weekday) <- c("1", "2", "3", "4", "5", "6", "7")
emnum$Weekday <- as.numeric(selected.df$Weekday)
levels(selected.df$Time) <- c("1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14","15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25")
emnum$Time <- as.numeric(selected.df$Time)
```


```R
library("PerformanceAnalytics")
chart.Correlation(emnum, method="spearman",histogram=TRUE,pch="16")

```


![png](images/output_21_0.png)



```R
library(corrr)

emnum %>% cor(method="spearman") %>% network_plot(min_cor=0.1)
```




![png](images/output_22_1.png)




## Build Model
### Partition Data
#### Create Training and Validation Sets


```R
# partition the data
train.index <- sample(1:nrow(em), nrow(em)*0.6)  
train.df <- selected.df[train.index, ]
valid.df <- selected.df[-train.index, ]
```



#### Fit a Logistic Regression Model


```R
logit.reg <- glm(CAT ~ Message+DMARC+Country+DKIM+Reputation+replyvsfrom+rpavsfrom+Weekday, data = train.df, family = "binomial")
summary(logit.reg)
```



    Call:
    glm(formula = CAT ~ Message + DMARC + Country + DKIM + Reputation +
        replyvsfrom + rpavsfrom + Weekday, family = "binomial", data = train.df)

    Deviance Residuals:
         Min        1Q    Median        3Q       Max  
    -3.09465  -0.18311  -0.04540  -0.00298   2.73259  

    Coefficients:
                   Estimate Std. Error z value Pr(>|z|)    
    (Intercept)  -4.880e+00  1.891e+00  -2.581 0.009848 **
    Message      -2.864e-05  1.803e-05  -1.589 0.112145    
    DMARC2       -1.101e+01  2.400e+03  -0.005 0.996340    
    DMARC3        6.306e+00  1.445e+00   4.364 1.28e-05 ***
    Country2      4.332e+00  1.767e+00   2.451 0.014247 *  
    DKIM2        -3.987e+00  2.255e+00  -1.768 0.077077 .  
    Reputation2   9.137e+00  2.607e+00   3.505 0.000457 ***
    replyvsfrom2 -5.052e+00  1.214e+00  -4.162 3.16e-05 ***
    rpavsfrom2   -2.141e+00  1.044e+00  -2.052 0.040209 *  
    Weekday2      3.313e+00  1.764e+00   1.878 0.060359 .  
    Weekday3      3.392e+00  1.544e+00   2.197 0.028011 *  
    Weekday4      6.549e-01  1.684e+00   0.389 0.697268    
    Weekday5      5.326e+00  1.607e+00   3.315 0.000918 ***
    Weekday6      1.686e+00  1.216e+00   1.387 0.165409    
    Weekday7      2.898e+00  1.634e+00   1.773 0.076224 .  
    ---
    Signif. codes:  0 '***' 0.001 '**' 0.01 '*' 0.05 '.' 0.1 ' ' 1

    (Dispersion parameter for binomial family taken to be 1)

        Null deviance: 172.126  on 162  degrees of freedom
    Residual deviance:  56.569  on 148  degrees of freedom
    AIC: 86.569

    Number of Fisher Scoring iterations: 15



#### Predction Validation


```R
logit.reg.pred <- predict(logit.reg, valid.df,  type = "response")
library(pROC)
r <- roc(valid.df$CAT, logit.reg.pred)
plot.roc(r)
pred <- ifelse(logit.reg.pred > coords(r, x = "best")[[1]], 1, 0)
print(coords(r, x = "best"))
```

    Type 'citation("pROC")' for a citation.

    Attaching package: 'pROC'

    The following objects are masked from 'package:stats':

        cov, smooth, var



      threshold specificity sensitivity
      0.3222076   0.9625000   0.9655172



![png](images/output_30_2.png)



```R
library(caret)
confusionMatrix(factor(pred), factor(valid.df$CAT), positive = "1")
```

    Loading required package: lattice
    Loading required package: ggplot2



    Confusion Matrix and Statistics

              Reference
    Prediction  0  1
             0 77  1
             1  3 28

                   Accuracy : 0.9633          
                     95% CI : (0.9087, 0.9899)
        No Information Rate : 0.7339          
        P-Value [Acc > NIR] : 2.433e-10       

                      Kappa : 0.9081          
     Mcnemar's Test P-Value : 0.6171          

                Sensitivity : 0.9655          
                Specificity : 0.9625          
             Pos Pred Value : 0.9032          
             Neg Pred Value : 0.9872          
                 Prevalence : 0.2661          
             Detection Rate : 0.2569          
       Detection Prevalence : 0.2844          
          Balanced Accuracy : 0.9640          

           'Positive' Class : 1               

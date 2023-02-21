FROM ubuntu:22.04
LABEL maintainer="Kenneth Dalgaard"


#RUN mkdir /projects

#testtest
ADD requirements.txt /usr

RUN apt-get update && apt-get install -y python3=3.10.6-1~22.04 python3-pip curl python-is-python3 sqlite3 iputils-ping python3.10-venv cron nano software-properties-common gnupg2 unzip wget \

&& pip install --no-cache-dir -r /usr/requirements.txt \
&& pip cache purge \
&& python -m pyclean /usr 

#RUN apt-get update && apt-get install -y \
#    wget \
#    unzip 
 # && rm -rf /var/lib/apt/lists/*

RUN wget --quiet https://releases.hashicorp.com/terraform/1.3.8/terraform_1.3.8_linux_amd64.zip 
RUN unzip terraform_1.3.8_linux_amd64.zip 
RUN mv terraform /usr/bin 
RUN rm terraform_1.3.8_linux_amd64.zip

ADD ntc-templates/ /usr/local/lib/python3.10/dist-packages/ntc_templates/templates/


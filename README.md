

## Indicator of Canary 

The Indicator of Canary is a collection of PoCs from research on identifying canaries in various file formats. It focuses on identifying known IoCs(Indicator of Canary) and unknown callback URLs in places they shouldn't be. Ultimately, this will give operators better awareness and make more informed decisions, preferably by automating similar checks in implants and other tools. 

There are other examples of tools on GitHub that perform regex searches for *.canarytoken.org; however, this doesn't represent a robust strategy for self-hosted or other vendors' canary documents. These scripts aim to raise known bad as red and potentially suspect as yellow, along with metadata to compare to other documents in the environment. 

Also included is a script to convert AWS Access keys to Account IDs to emphasize further that if you have access to multiple access keys, you can potentially find outliers with uncommon account IDs, which might require additional scruinitiy to validate.  Canary providers also often use the same account ID across their canary fleet. 

## Files

sample_data - Samples from 4 Canary providers<br>
aws_id_convert.py - Convert AWS Key to AWS Account ID(compare to known Account IDs)<br>
docx_canary.py - Extract .docx canaries<br>
docx_patch.py - Overwrite .docx canaries<br>
mysql_canary.py - Extract MySQL dump canaries<br>
pdf_canary.notes - Extract .pdf canaries im lazy<br>
pptx_canary.py - Extract .pptx canaries<br>
static_iocs.txt - IoCs from various vendors<br>
xlsx_canary.py - Extract .xlsx canaries<br>

## Screenshots

![docx](https://github.com/HackingLZ/IndicatorOfCanary/blob/main/screenshots/docx.jpg)


![xlsx](https://github.com/HackingLZ/IndicatorOfCanary/blob/main/screenshots/xlsx.jpg)


## Additional Details 

The PoCs will work agaisn't multiple vendors canary solutions 

Extension of this Gist from 2022 - https://gist.github.com/HackingLZ/0285d248f648f5dd216758c3fbf78c97

1. **Start with clear objective** - know exactly what you're testing. define harm/threat/safety domains (e.g. bias, misinformation, PII leakage, self harm etc)
2. **iterate with purpose** - treat prompt attacks like long lasting conversations that evolve overtime. Each prompt builds off the previous one. adjust strategy without deviating from goal/objective from step 1. 
3. **maintain persona discipline** - if you use a role, character or scenario to set the conversation then stick to it and reinforce it often throughout the conversation to keep he AI in character. 
4. **use gradual escalation**  - increase pressure on the AI step by step. start general then specific then push boundaries. document where the AI changes tone or compliance. 
5. **keep prompts tight and focused** - one prompt with one purpose at a time. don't overload or overword with long contradictory prompts. multiple shorter prompt conversations that build overtime find more than one big wall of text paragraph.
6. **evaluate harm/threat/safety/boundary objectively** - separate true unsafe or harmful outputs from benign or factual bias outputs. avoid false positives and false negatives. stick to the objective in step 1. 
7. **handle dual use prompts carefully** - treat ambiguity as a data not as intent. observe and document it. document edge cases and if the AI over or under blocked it or reacted in unexpected ways. goal is not to make the AI fail but to document how it handles grey areas. does it react as expected based on objectives in step one and known harm/safety/threat categories or does it react in unexpected uncategorized or harmful ways? document all the above for each test case/objective/goal/hypothesis. how does the AI work and why? does it properly implement mitigations against the attack objectives in step 1? 



**report summary items to be sure to capture for test recreation:** repeat this format for each test case and then write an executive summary to include overall scope and patterns or trends etc in addition to the detailed test results in the format below. 



**AI red teaming results report:**



Attack Objective/Intent/Hypothesis:



Prompt 1:





Response 1:





Prompt 2: 





Response 2:





Prompt 3:





Response 3:



Safety/Harm/Threat/Risk/Attack Category:

Attack type:

Mitigation Recommendation: NIST, OWASP, MITRE hardening practices, requirement, control, example etc. 


                                            EDOauthAPp

I created this app to make it easier for people to write their own IOS App for accessing the CMDR Data from Frontier, using their Ouath Implementation.
As Built on 8 Dec 2019 it work seemlessly. I may or may not update if anything gets broken, but at least this is a good point to start from.


Many Thanks to Anthanasius for working on alot of the background to how Frontier uses Oauth, and how CAPI works.

Read all the Docs here 
https://github.com/Athanasius/fd-api/tree/master/docs

Make sure you have registered your App with Frontier and got your CLienID and Shared Key.
https://user.frontierstore.net/developer

When Testing, i always goto the 'authorised Apps' and 'Deauthorise' on the Froniter Website.
When Authorising any '500' Sever error from Frontier means that you haven't formed the Authorisation URL. Could be the Secret, key, code Verifier, etc.... It should all work. Check you have updated the Key & Secret changign from ******* to your values.


Also read OAuthSwift - Albeit some of this is outdated, but the principles apply. ( eg Oauth_token is no oauthToken.


https://github.com/OAuthSwift/OAuthSwift

Make sure you configure your URL-Scheme, and i'd use the whole Bundle ID as i did below.
Click your App name on the Folder view and find the Info Pane, then go down to URL Types.
Click + to add a new one.

Use the Bundle ID eg com.cerbyinnovations.EDOauthApp as teh Identifier.
Use AppName eg EDOAuthApp as the URL Scheme.

I used Prephirenes to make it easy to store tokens in the keychain.
https://github.com/phimage/Prephirences

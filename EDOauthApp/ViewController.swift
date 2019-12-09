//
//  ViewController.swift
//  EDOauthApp
//
//  Created by Peter Provart on 09/12/2019.
//  Copyright © 2019 Peter Provart. All rights reserved.
//

import UIKit
import CommonCrypto
import SafariServices
import Foundation
import Alamofire
import OAuthSwift
import SwiftyJSON
import Prephirences


class ViewController: UIViewController {
    
    // Make an instance of the Keychain dealer
    var keychain = KeychainPreferences.sharedInstance
    
    // The CLIENT-ID and SHARED_KEY are created by Frontier when you register your app, get them and enter Here.
    let frontierClientIdIsKey = "******************"
    let frontierSharedKeyIsSecret = "******************"
    
    // Created a Global Instance of Oauth, used for the Callback data to pass between the UI's & Important to Initialise it.
    var oauthswift = OAuth2Swift(
        consumerKey:    "******************", //Client ID from Frontier
        consumerSecret: "******************", //Shared Key from Frontier
        authorizeUrl: "https://auth.frontierstore.net/auth",
        accessTokenUrl: "https://auth.frontierstore.net/token",
        responseType: "code"
    )
    var accessToken : String = ""
//    var refreshToken : String = ""
//    var credential : OAuthSwiftCredential?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
        //retrieveTheTokens()
        // Retrieve OautTokens, refresh token from Keychain.
        if let accessToken = keychain.string(forKey: "the_token_key") {
            print("Access Token " + "\(accessToken)")
//            sets the oauthtoken in the global instance
            self.oauthswift.client.credential.oauthToken = accessToken
            print ("\(oauthswift.client.credential.oauthToken)")
        }
        else  {
            print ("No AccessToken ovveride")
        }
        if let refreshToken = keychain.string(forKey: "the_refresh_token") {
            print("Refresh Token " + "\(refreshToken)")
            self.oauthswift.client.credential.oauthRefreshToken = refreshToken
        }
        else  {
            print ("No RefreshToken ovveride")
        }
//        if let secretToken = keychain.string(forKey: "the_secret_token_key") {
//            print("Secret Token " + "\(secretToken)")
//            self.oauthswift.client.credential.oauthTokenSecret = secretToken
//        }
//        else  {
//            print ("No RefreshToken ovveride")
//        }
    }
 //MARK : Insert NEw IB Action here
    
    @IBAction func doAuthFunc(_ sender: UIButton) {
        print("Get Oauth Button Pressed")
        frontierOauth() //Launch Oauth process when the button is preossed.
    }
    
    @IBAction func getCmdrData(_ sender: UIButton) {
        print ("Pressed GET CMDR")
        print ("Global Oauth Token is " + "\(self.oauthswift.client.credential.oauthToken)")
        getFrontier( ) //Get the Profile from Frontier.
    }
    
    @IBOutlet weak var cmdrName: UILabel!
    
    @IBOutlet weak var CMDRLocation: UILabel!
    
    // InfoPane Text Label has been set to display 20 lines in Storyboard.
    @IBOutlet weak var infoPane: UILabel!
    
    

    //URLS for AUthorisation.
    let SERVER_AUTH = "https://auth.frontierstore.net"
    let URL_AUTH    = "/auth"
    let URL_TOKEN   = "/token"
    // URLS For getting Data from Frontier.
    let SERVER_LIVE = "https://companion.orerve.net"
    let SERVER_BETA = "https://pts-companion.orerve.net"
    let URL_QUERY   = "/profile"
    let URL_MARKET  = "/market"
    let URL_SHIPYARD = "/shipyard"
    

    // Defined the Authorisation Function to run when the Oauth button is pressed.
    func frontierOauth  () {
         print ("Heelo World")
    
    // create Code Verifier
    var buffer = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, buffer.count, &buffer)
    let verifier = Data(_: buffer).base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
    .trimmingCharacters(in: .whitespaces)
        
    // create State of 32 chats using the Oauth State generator. State is used to check what is returned by Frontier matches the Challnege sent etc.
    let stateST = generateState(withLength: 32)

    //Define Code Challenge Function.
    func createCodeC (_ codedata: String) -> String? {
    guard let data = codedata.data(using: .utf8) else { return nil }
    var ccbuffer = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &ccbuffer)
    }
        
    // Below makes it URL friendly.
    let hash = Data(_: ccbuffer)
    let challenge = hash.base64EncodedString()
    .replacingOccurrences(of: "+", with: "-")
    .replacingOccurrences(of: "/", with: "_")
    .replacingOccurrences(of: "=", with: "")
    .trimmingCharacters(in: .whitespaces)
    return challenge
    //end Code CodeChallnge
    }
    
    
    // create a local instance of Oauth using the parameters given by Frontier.
    let loauthswift = OAuth2Swift(
        consumerKey: self.frontierClientIdIsKey,
        consumerSecret: self.frontierSharedKeyIsSecret,
        authorizeUrl: "https://auth.frontierstore.net/auth",
        accessTokenUrl: "https://auth.frontierstore.net/token",
        responseType: "code"
    )
    
        loauthswift.accessTokenBasicAuthentification = true
    // Uses Safari Browser to handle the Authentication to Frontier. IN essence PKCe needs us to popup a window let the user authenticate, and then Frontier will return to the Callback URL the Token. This is handled by SceneDelegate in IOS13.( Check comments there )
    loauthswift.authorizeURLHandler = SafariURLHandler(viewController: self  , oauthSwift: oauthswift)
    
    // Create the Verifier, Code Challenge and State to be used.
    let codeVerifier = verifier
    let codeChallenge = createCodeC(verifier)
    let newState = stateST
    
    print (codeChallenge)
    // Copies Local Oauth to Global.
    self.oauthswift = loauthswift
        
    // Inialise the handler to handle the authorisaiton function.
    let handle =
        loauthswift.authorize(
            // OauthSiftTest is this app name and /callback is the 'hostname' typical URI definition. Need to set in URL Schemes.
        withCallbackURL: URL(string: "EDOauthApp://callback/")!,
        scope: "capi",
        state: newState,
        codeChallenge: codeChallenge!,
        codeChallengeMethod: "S256",
        codeVerifier: codeVerifier) { result in
            switch result {
            case .success(let (credential, _, _)):
                print("Case Sucess")
                print(credential.oauthToken)
                self.oauthswift = loauthswift //Update Global With Local
                self.storeTokens(toauthswift: loauthswift) //Store new tokens in keychain.
            // Do your error handling
            case .failure(let error):
                print("Case error")
                print(error.localizedDescription)
            }
    }

    }
    
    // Gets the CMDR Data from frontier. No arguments passed to it , as will used the Global oauth instance. This is because we MAY pull in tokens from keychain on startup, or copy the Oauth type from the Authorisation ( ie when we copy loauthswift to oauthswift.
    func getFrontier() {
        let _ = self.oauthswift.client.get(
            "https://companion.orerve.net/profile",
            parameters: [:]) { result in
                switch result {
                case .success(let response):
                    let jsonSrc = try! response.jsonObject()
                    // uses Swifty JSon to interpret the JSON thingy returned by Frontier.
                    let jsonDict : JSON =  JSON(jsonSrc)
                    // Search for some CMDR specific data to display.
                    if let cmdrDataSystemName : String = jsonDict["lastSystem"]["name"].stringValue { print("\(cmdrDataSystemName)")
                        // Chance the Display Labels to the retrieved text.
                        self.CMDRLocation.text = cmdrDataSystemName
                        print("DSiaplyInfo = " + "\(self.CMDRLocation.text)")
                    }
                    if let cmdrDataSystemID : Int = jsonDict["lastSystem"]["id"].intValue{
                        print ("\(cmdrDataSystemID)")
                    }
                    if let cmdrNameID : String = jsonDict["commander"]["name"].stringValue{
                        print ("\(cmdrNameID)")
                        self.cmdrName.text = cmdrNameID
                        print("DSiaplyInfo = " + "\(self.cmdrName.text)")
                    }
                    print(jsonDict as Any) //just print whole disctionary to debug window.
                    // Below takes teh raw dicitonary and send to the Info Pane ( 20 lines only )
                    self.infoPane.text = "\(jsonDict.rawString() )"
                case .failure(let error):
                    print(error.description)
                }
        }
        }
    // Stores the Oauth tokens in keychain uses Prephirences
    // Passes the Oauth instance to the function to extract the right tokens etc.
    func storeTokens(toauthswift: OAuth2Swift){
        //Print the OuathToken
        print ("Oauth token stored is  " + "\(toauthswift.client.credential.oauthToken)")
        self.keychain["the_token_key"] = toauthswift.client.credential.oauthToken
        // Dont think the 'Secret' is genrated/stored as always appear empty.
        self.keychain["the_secret_token_key"] = toauthswift.client.credential.oauthTokenSecret
        self.keychain["the_refresh_token"] = toauthswift.client.credential.oauthRefreshToken
    }
    

    
}



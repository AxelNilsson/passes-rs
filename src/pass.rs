use serde::{Deserialize, Serialize};

use self::visual_appearance::VisualAppearance;

pub mod visual_appearance;

/// Represents a pass (pass.json file)
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Pass {
    /// (Required) The version of the file format. The value must be 1.
    pub format_version: u32,

    /// (Required) The name of the organization.
    pub organization_name: String,

    /// (Required) A short description that iOS accessibility technologies use for a pass.
    pub description: String,

    /// (Required) The pass type identifier that’s registered with Apple.
    /// The value must be the same as the distribution certificate used to sign the pass.
    pub pass_type_identifier: String,

    /// (Required) The Team ID for the Apple Developer Program account that registered the pass type identifier.
    pub team_identifier: String,

    /// (Required) An alphanumeric serial number.
    /// The combination of the serial number and pass type identifier must be unique for each pass.
    pub serial_number: String,

    /// An identifier the system uses to group related boarding passes or event tickets.
    /// Wallet displays passes with the same [grouping_identifier](Pass::grouping_identifier), [pass_type_identifier](Pass::pass_type_identifier), and type as a group.
    /// Use this identifier to group passes that are tightly related, such as boarding passes for different connections on the same trip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grouping_identifier: Option<String>,

    /// Colors and other visual parts of the pass
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub appearance: Option<VisualAppearance>,

    /// The text to display next to the logo on the pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_text: Option<String>,

    /// The date and time when the pass becomes relevant
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relevant_date: Option<String>,

    /// The date and time the pass expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,

    /// A URL to be passed to the associated app when launching it.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "appLaunchURL")]
    pub app_launch_url: Option<String>,

    /// An array of App Store identifiers for apps associated with the pass.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub associated_store_identifiers: Vec<i32>,

    /// The authentication token to use with the web service in the [web_service_url](Pass::web_service_url) key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication_token: Option<String>,

    /// The URL for a web service that you use to update or personalize the pass. The URL can include an optional port number.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "webServiceURL")]
    pub web_service_url: Option<String>,

    /// Controls whether to show the Share button on the back of a pass.
    /// A value of true removes the button. The default value is false.
    /// This flag has no effect in earlier versions of iOS, nor does it prevent sharing the pass in some other way.
    #[serde(skip_serializing_if = "is_false")]
    pub sharing_prohibited: bool,

    /// Controls whether to display the strip image without a shine effect.
    /// The default value is true.
    #[serde(skip_serializing_if = "is_true")]
    pub suppress_strip_shine: bool,

    /// Indicates that the pass is void, such as a redeemed, one-time-use coupon.
    /// The default value is false.
    #[serde(skip_serializing_if = "is_false")]
    pub voided: bool,

    // TODO: Barcode on a pass
    // The system uses the first displayable barcode for the device.
    // pub barcodes: Vec<Barcode>,

    // TODO: Array of Bluetooth Low Energy beacons the system uses to show a relevant pass.
    // pub beacons: Vec<Beacon>,

    // TODO: An array of up to 10 geographic locations the system uses to show a relevant pass.
    // pub locations: Vec<Location>,
    /// The maximum distance, in meters, from a location in the [locations](Pass::locations) array at which the pass is relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_distance: Option<u32>,
    // TODO: NFC
    // pub nfc: Option<NFC>,

    // TODO: Semantic tags
    // Metadata the system uses to offer a pass and suggest related actions.
    // For example, setting Don’t Disturb mode for the duration of a movie.
    // pub semantics: Vec<SemanticTag>,

    // TODO: PassTypes
    // boarding pass
    // coupon
    // event ticket
    // generic

    // TODO: UserInfo
    // custom JSOM
}

/// Builder for pass (represents pass.json file)
pub struct PassBuilder {
    pass: Pass,
}

impl PassBuilder {
    /// Creates builder for `Pass`.
    pub fn new(
        organization_name: String,
        description: String,
        pass_type_identifier: String,
        team_identifier: String,
        serial_number: String,
    ) -> Self {
        let pass = Pass {
            // setup required vars
            format_version: 1,
            organization_name,
            description,
            pass_type_identifier,
            team_identifier,
            serial_number,
            // Setup default vars
            grouping_identifier: None,
            appearance: None,
            logo_text: None,
            relevant_date: None,
            expiration_date: None,
            app_launch_url: None,
            associated_store_identifiers: Vec::new(),
            authentication_token: None,
            web_service_url: None,
            sharing_prohibited: false,
            suppress_strip_shine: true,
            voided: false,
            max_distance: None,
        };
        Self { pass }
    }

    /// Adding [grouping_identifier](Pass::grouping_identifier)
    pub fn grouping_identifier(mut self, field: String) -> PassBuilder {
        self.pass.grouping_identifier = Some(field);
        self
    }

    /// Adding [appearance](Pass::appearance).
    pub fn appearance(mut self, field: VisualAppearance) -> PassBuilder {
        self.pass.appearance = Some(field);
        self
    }

    /// Adding [logo_text](Pass::logo_text)
    pub fn logo_text(mut self, field: String) -> PassBuilder {
        self.pass.logo_text = Some(field);
        self
    }

    /// Adding [relevant_date](Pass::relevant_date)
    pub fn relevant_date(mut self, field: String) -> PassBuilder {
        self.pass.relevant_date = Some(field);
        self
    }

    /// Adding [expiration_date](Pass::expiration_date)
    pub fn expiration_date(mut self, field: String) -> PassBuilder {
        self.pass.expiration_date = Some(field);
        self
    }

    /// Adding [app_launch_url](Pass::app_launch_url)
    pub fn app_launch_url(mut self, field: String) -> PassBuilder {
        self.pass.app_launch_url = Some(field);
        self
    }

    /// Adding [associated_store_identifiers](Pass::associated_store_identifiers)
    pub fn add_associated_store_identifier(mut self, id: i32) -> PassBuilder {
        self.pass.associated_store_identifiers.push(id);
        self
    }

    /// Adding [authentication_token](Pass::authentication_token)
    pub fn authentication_token(mut self, field: String) -> PassBuilder {
        self.pass.authentication_token = Some(field);
        self
    }

    /// Adding [web_service_url](Pass::web_service_url)
    pub fn web_service_url(mut self, field: String) -> PassBuilder {
        self.pass.web_service_url = Some(field);
        self
    }

    /// Adding [sharing_prohibited](Pass::sharing_prohibited)
    pub fn set_sharing_prohibited(mut self, field: bool) -> PassBuilder {
        self.pass.sharing_prohibited = field;
        self
    }

    /// Adding [suppress_strip_shine](Pass::suppress_strip_shine)
    pub fn set_suppress_strip_shine(mut self, field: bool) -> PassBuilder {
        self.pass.suppress_strip_shine = field;
        self
    }

    /// Adding [voided](Pass::voided)
    pub fn voided(mut self, field: bool) -> PassBuilder {
        self.pass.voided = field;
        self
    }

    /// Adding [max_distance](Pass::max_distance)
    pub fn max_distance(mut self, field: u32) -> PassBuilder {
        self.pass.max_distance = Some(field);
        self
    }

    /// Makes `Pass`.
    pub fn build(self) -> Pass {
        self.pass
    }
}

#[cfg(test)]
mod tests {
    use tests::visual_appearance::Color;

    use super::*;

    #[test]
    fn make_minimal_pass() {
        let pass = PassBuilder::new(
            String::from("Apple inc."),
            String::from("Example pass"),
            String::from("com.example.pass"),
            String::from("AA00AA0A0A"),
            String::from("ABCDEFG1234567890"),
        )
        .build();

        let json = serde_json::to_string_pretty(&pass).unwrap();

        println!("{}", serde_json::to_string_pretty(&pass).unwrap());

        let json_expected = r#"{
  "formatVersion": 1,
  "organizationName": "Apple inc.",
  "description": "Example pass",
  "passTypeIdentifier": "com.example.pass",
  "teamIdentifier": "AA00AA0A0A",
  "serialNumber": "ABCDEFG1234567890"
}"#;

        assert_eq!(json_expected, json);
    }

    #[test]
    fn make_pass() {
        let pass = PassBuilder::new(
            String::from("Apple inc."),
            String::from("Example pass"),
            String::from("com.example.pass"),
            String::from("AA00AA0A0A"),
            String::from("ABCDEFG1234567890"),
        )
        .grouping_identifier(String::from("com.example.pass.app"))
        .appearance(VisualAppearance {
            label_color: None,
            foreground_color: Color::new(250, 10, 10),
            background_color: Color::white(),
        })
        .logo_text(String::from("Test pass"))
        .relevant_date(String::from("2024-02-07T00:00"))
        .expiration_date(String::from("2024-02-08T00:00"))
        .app_launch_url(String::from("testapp:param?index=1"))
        .add_associated_store_identifier(100)
        .authentication_token(String::from("abcdefg01234567890abcdefg"))
        .web_service_url(String::from("https://example.com/passes/"))
        .set_sharing_prohibited(false)
        .set_suppress_strip_shine(false)
        .voided(false)
        .max_distance(1000)
        .build();

        let json = serde_json::to_string_pretty(&pass).unwrap();

        println!("{}", serde_json::to_string_pretty(&pass).unwrap());

        let json_expected = r#"{
  "formatVersion": 1,
  "organizationName": "Apple inc.",
  "description": "Example pass",
  "passTypeIdentifier": "com.example.pass",
  "teamIdentifier": "AA00AA0A0A",
  "serialNumber": "ABCDEFG1234567890",
  "groupingIdentifier": "com.example.pass.app",
  "foregroundColor": "rgb(250, 10, 10)",
  "backgroundColor": "rgb(255, 255, 255)",
  "logoText": "Test pass",
  "relevantDate": "2024-02-07T00:00",
  "expirationDate": "2024-02-08T00:00",
  "appLaunchURL": "testapp:param?index=1",
  "associatedStoreIdentifiers": [
    100
  ],
  "authenticationToken": "abcdefg01234567890abcdefg",
  "webServiceURL": "https://example.com/passes/",
  "suppressStripShine": false,
  "maxDistance": 1000
}"#;

        assert_eq!(json_expected, json);
    }
}

// For serde skipping - if boolean false
fn is_false(b: &bool) -> bool {
    !b
}
// For serde skipping - if boolean true
fn is_true(b: &bool) -> bool {
    *b
}

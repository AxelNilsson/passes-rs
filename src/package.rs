use std::{
    io::{Read, Seek, Write},
    str::FromStr,
};

use crate::pass::Pass;

use self::{manifest::Manifest, resource::Resource, sign::SignConfig};

pub mod manifest;
pub mod resource;
pub mod sign;

/// Pass Package, contains information about pass.json, images, manifest.json and signature.
pub struct Package {
    /// Represents pass.json
    pub pass: Pass,

    /// Resources (image files)
    pub resources: Vec<Resource>,

    // Certificates for signing package
    pub sign_config: Option<SignConfig>,
}

impl Package {
    /// Create new package
    pub fn new(pass: Pass) -> Self {
        Self {
            pass,
            resources: vec![],
            sign_config: None,
        }
    }

    /// Read compressed package (.pkpass) from file.
    ///
    /// Use for creating .pkpass file from template.
    pub fn read<R: Read + Seek>(reader: R) -> Result<Self, &'static str> {
        // Read .pkpass as zip
        let mut zip = zip::ZipArchive::new(reader).expect("Error unzipping pkpass");

        let mut pass: Option<Pass> = None;
        let mut resources = Vec::<Resource>::new();

        for i in 0..zip.len() {
            // Get file name
            let mut file = zip.by_index(i).unwrap();
            let filename = file.name();
            // Read pass.json file
            if filename == "pass.json" {
                let mut buf = String::new();
                file.read_to_string(&mut buf)
                    .expect("Error while reading pass.json");
                pass = Some(Pass::from_json(&buf).expect("Error while parsing pass.json"));
                continue;
            }
            // Read resource files
            match resource::Type::from_str(filename) {
                // Match resource type by template
                Ok(t) => {
                    let mut resource = Resource::new(t);
                    std::io::copy(&mut file, &mut resource)
                        .expect("Error while reading resource file");
                    resources.push(resource);
                }
                // Skip unknown files
                Err(_) => {}
            }
        }

        // Check is pass.json successfully read
        if let Some(pass) = pass {
            Ok(Self {
                pass,
                resources,
                sign_config: None,
            })
        } else {
            Err("pass.json is missed in package file")
        }
    }

    /// Add certificates for signing package
    pub fn add_certificates(&mut self, config: SignConfig) {
        self.sign_config = Some(config);
    }

    /// Write compressed package.
    ///
    /// Use for creating .pkpass file
    pub fn write<W: Write + Seek>(&mut self, writer: W) -> Result<(), &'static str> {
        let mut manifest = Manifest::new();

        let mut zip = zip::ZipWriter::new(writer);
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        // Adding pass.json to zip
        zip.start_file("pass.json", options)
            .expect("Error while creating pass.json in zip");
        let pass_json = self
            .pass
            .make_json()
            .expect("Error while building pass.json");
        zip.write_all(pass_json.as_bytes())
            .expect("Error while writing pass.json in zip");
        manifest.add_item("pass.json", pass_json.as_bytes());

        // Adding each resource files to zip
        for resource in &self.resources {
            zip.start_file(resource.filename(), options)
                .expect("Error while creating resource file in zip");
            zip.write_all(resource.as_bytes())
                .expect("Error while writing resource file in zip");
            manifest.add_item(resource.filename().as_str(), resource.as_bytes());
        }

        // Adding manifest.json to zip
        zip.start_file("manifest.json", options)
            .expect("Error while creating manifest.json in zip");
        let manifest_json = manifest
            .make_json()
            .expect("Error while generating manifest file");
        zip.write_all(manifest_json.as_bytes())
            .expect("Error while writing manifest.json in zip");
        manifest.add_item("manifest.json", manifest_json.as_bytes());

        // If SignConfig is provided, make signature
        if let Some(sign_config) = &self.sign_config {
            let signature_data = sign_config
                .generate_p7b()
                .expect("Error while generating p7b signature");

            // The rest of the code for adding the signature to the zip file remains unchanged

            // Adding signature to zip
            zip.start_file("signature", options)
                .expect("Error while creating signature in zip");
            zip.write_all(&signature_data)
                .expect("Error while writing signature in zip");
        }

        zip.finish().expect("Error while saving zip");

        Ok(())
    }

    /// Adding image file to package.
    ///
    /// Reading file to internal buffer storage.
    pub fn add_resource<R: Read>(
        &mut self,
        image_type: resource::Type,
        mut reader: R,
    ) -> Result<(), &'static str> {
        let mut resource = Resource::new(image_type);
        std::io::copy(&mut reader, &mut resource).expect("Error while reading resource");
        self.resources.push(resource);
        Ok(())
    }
}

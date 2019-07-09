# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # The set of changes to be made to a Pool.
    #
    #
    class PoolUpdatePropertiesParameter

      include MsRestAzure

      # @return [StartTask] A Task to run on each Compute Node as it joins the
      # Pool. The Task runs when the Compute Node is added to the Pool or when
      # the Compute Node is restarted. If this element is present, it
      # overwrites any existing start Task. If omitted, any existing start Task
      # is removed from the Pool.
      attr_accessor :start_task

      # @return [Array<CertificateReference>] A list of Certificates to be
      # installed on each Compute Node in the Pool. This list replaces any
      # existing Certificate references configured on the Pool. If you specify
      # an empty collection, any existing Certificate references are removed
      # from the Pool. For Windows Nodes, the Batch service installs the
      # Certificates to the specified Certificate store and location. For Linux
      # Compute Nodes, the Certificates are stored in a directory inside the
      # Task working directory and an environment variable
      # AZ_BATCH_CERTIFICATES_DIR is supplied to the Task to query for this
      # location. For Certificates with visibility of 'remoteUser', a 'certs'
      # directory is created in the user's home directory (e.g.,
      # /home/{user-name}/certs) and Certificates are placed in that directory.
      attr_accessor :certificate_references

      # @return [Array<ApplicationPackageReference>] The list of Application
      # Packages to be installed on each Compute Node in the Pool. The list
      # replaces any existing Application Package references on the Pool.
      # Changes to Application Package references affect all new Compute Nodes
      # joining the Pool, but do not affect Compute Nodes that are already in
      # the Pool until they are rebooted or reimaged. There is a maximum of 10
      # Application Package references on any given Pool. If omitted, or if you
      # specify an empty collection, any existing Application Packages
      # references are removed from the Pool. A maximum of 10 references may be
      # specified on a given Pool.
      attr_accessor :application_package_references

      # @return [Array<MetadataItem>] A list of name-value pairs associated
      # with the Pool as metadata. This list replaces any existing metadata
      # configured on the Pool. If omitted, or if you specify an empty
      # collection, any existing metadata is removed from the Pool.
      attr_accessor :metadata


      #
      # Mapper for PoolUpdatePropertiesParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'PoolUpdatePropertiesParameter',
          type: {
            name: 'Composite',
            class_name: 'PoolUpdatePropertiesParameter',
            model_properties: {
              start_task: {
                client_side_validation: true,
                required: false,
                serialized_name: 'startTask',
                type: {
                  name: 'Composite',
                  class_name: 'StartTask'
                }
              },
              certificate_references: {
                client_side_validation: true,
                required: true,
                serialized_name: 'certificateReferences',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'CertificateReferenceElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'CertificateReference'
                      }
                  }
                }
              },
              application_package_references: {
                client_side_validation: true,
                required: true,
                serialized_name: 'applicationPackageReferences',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'ApplicationPackageReferenceElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'ApplicationPackageReference'
                      }
                  }
                }
              },
              metadata: {
                client_side_validation: true,
                required: true,
                serialized_name: 'metadata',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'MetadataItemElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'MetadataItem'
                      }
                  }
                }
              }
            }
          }
        }
      end
    end
  end
end
# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_12_01_8_0
  module Models
    #
    # The set of changes to be made to a pool.
    #
    #
    class PoolPatchParameter

      include MsRestAzure

      # @return [StartTask] A task to run on each compute node as it joins the
      # pool. The task runs when the node is added to the pool or when the node
      # is restarted. If this element is present, it overwrites any existing
      # start task. If omitted, any existing start task is left unchanged.
      attr_accessor :start_task

      # @return [Array<CertificateReference>] A list of certificates to be
      # installed on each compute node in the pool. If this element is present,
      # it replaces any existing certificate references configured on the pool.
      # If omitted, any existing certificate references are left unchanged. For
      # Windows compute nodes, the Batch service installs the certificates to
      # the specified certificate store and location. For Linux compute nodes,
      # the certificates are stored in a directory inside the task working
      # directory and an environment variable AZ_BATCH_CERTIFICATES_DIR is
      # supplied to the task to query for this location. For certificates with
      # visibility of 'remoteUser', a 'certs' directory is created in the
      # user's home directory (e.g., /home/{user-name}/certs) and certificates
      # are placed in that directory.
      attr_accessor :certificate_references

      # @return [Array<ApplicationPackageReference>] The list of application
      # packages to be installed on each compute node in the pool. The list
      # replaces any existing application package references on the pool.
      # Changes to application package references affect all new compute nodes
      # joining the pool, but do not affect compute nodes that are already in
      # the pool until they are rebooted or reimaged. There is a maximum of 10
      # application package references on any given pool. If omitted, any
      # existing application package references are left unchanged.
      attr_accessor :application_package_references

      # @return [Array<MetadataItem>] A list of name-value pairs associated
      # with the pool as metadata. If this element is present, it replaces any
      # existing metadata configured on the pool. If you specify an empty
      # collection, any metadata is removed from the pool. If omitted, any
      # existing metadata is left unchanged.
      attr_accessor :metadata


      #
      # Mapper for PoolPatchParameter class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'PoolPatchParameter',
          type: {
            name: 'Composite',
            class_name: 'PoolPatchParameter',
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
                required: false,
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
                required: false,
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
                required: false,
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

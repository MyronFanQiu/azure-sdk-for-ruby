# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_08_01_7_0
  module Models
    #
    # A reference to an application package to be deployed to compute nodes.
    #
    #
    class ApplicationPackageReference

      include MsRestAzure

      # @return [String] The ID of the application to deploy.
      attr_accessor :application_id

      # @return [String] The version of the application to deploy. If omitted,
      # the default version is deployed. If this is omitted on a pool, and no
      # default version is specified for this application, the request fails
      # with the error code InvalidApplicationPackageReferences and HTTP status
      # code 409. If this is omitted on a task, and no default version is
      # specified for this application, the task fails with a pre-processing
      # error.
      attr_accessor :version


      #
      # Mapper for ApplicationPackageReference class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ApplicationPackageReference',
          type: {
            name: 'Composite',
            class_name: 'ApplicationPackageReference',
            model_properties: {
              application_id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'applicationId',
                type: {
                  name: 'String'
                }
              },
              version: {
                client_side_validation: true,
                required: false,
                serialized_name: 'version',
                type: {
                  name: 'String'
                }
              }
            }
          }
        }
      end
    end
  end
end

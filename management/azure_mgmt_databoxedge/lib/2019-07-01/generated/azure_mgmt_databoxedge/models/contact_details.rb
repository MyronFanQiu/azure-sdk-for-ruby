# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_07_01
  module Models
    #
    # Contains all the contact details of the customer.
    #
    class ContactDetails

      include MsRestAzure

      # @return [String] The contact person name.
      attr_accessor :contact_person

      # @return [String] The name of the company.
      attr_accessor :company_name

      # @return [String] The phone number.
      attr_accessor :phone

      # @return [Array<String>] The email list.
      attr_accessor :email_list


      #
      # Mapper for ContactDetails class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ContactDetails',
          type: {
            name: 'Composite',
            class_name: 'ContactDetails',
            model_properties: {
              contact_person: {
                client_side_validation: true,
                required: true,
                serialized_name: 'contactPerson',
                type: {
                  name: 'String'
                }
              },
              company_name: {
                client_side_validation: true,
                required: true,
                serialized_name: 'companyName',
                type: {
                  name: 'String'
                }
              },
              phone: {
                client_side_validation: true,
                required: true,
                serialized_name: 'phone',
                type: {
                  name: 'String'
                }
              },
              email_list: {
                client_side_validation: true,
                required: true,
                serialized_name: 'emailList',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'StringElementType',
                      type: {
                        name: 'String'
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

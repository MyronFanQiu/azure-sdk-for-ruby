# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::CognitiveServices::ImageSearch::V1_0
  module Models
    #
    # The top-level object that the response includes when an image insights
    # request succeeds. For information about requesting image insights, see
    # the
    # [insightsToken](https://docs.microsoft.com/en-us/rest/api/cognitiveservices/bing-images-api-v7-reference#insightstoken)
    # query parameter. The modules query parameter affects the fields that Bing
    # includes in the response. If you set
    # [modules](https://docs.microsoft.com/en-us/rest/api/cognitiveservices/bing-images-api-v7-reference#modulesrequested)
    # to only Caption, then this object includes only the imageCaption field.
    #
    class ImageInsights < Response

      include MsRestAzure


      def initialize
        @_type = "ImageInsights"
      end

      attr_accessor :_type

      # @return [String] A token that you use in a subsequent call to the Image
      # Search API to get more information about the image. For information
      # about using this token, see the insightsToken query parameter. This
      # token has the same usage as the token in the Image object.
      attr_accessor :image_insights_token

      # @return [Query] The query term that best represents the image. Clicking
      # the link in the Query object, takes the user to a webpage with more
      # pictures of the image.
      attr_accessor :best_representative_query

      # @return [ImageInsightsImageCaption] The caption to use for the image.
      attr_accessor :image_caption

      # @return [RelatedCollectionsModule] A list of links to webpages that
      # contain related images.
      attr_accessor :related_collections

      # @return [ImagesModule] A list of webpages that contain the image. To
      # access the webpage, use the URL in the image's hostPageUrl field.
      attr_accessor :pages_including

      # @return [AggregateOffer] A list of merchants that offer items related
      # to the image. For example, if the image is of an apple pie, the list
      # contains merchants that are selling apple pies.
      attr_accessor :shopping_sources

      # @return [RelatedSearchesModule] A list of related queries made by
      # others.
      attr_accessor :related_searches

      # @return [RecipesModule] A list of recipes related to the image. For
      # example, if the image is of an apple pie, the list contains recipes for
      # making an apple pie.
      attr_accessor :recipes

      # @return [ImagesModule] A list of images that are visually similar to
      # the original image. For example, if the specified image is of a sunset
      # over a body of water, the list of similar images are of a sunset over a
      # body of water. If the specified image is of a person, similar images
      # might be of the same person or they might be of persons dressed
      # similarly or in a similar setting. The criteria for similarity
      # continues to evolve.
      attr_accessor :visually_similar_images

      # @return [ImagesModule] A list of images that contain products that are
      # visually similar to products found in the original image. For example,
      # if the specified image contains a dress, the list of similar images
      # contain a dress. The image provides summary information about offers
      # that Bing found online for the product.
      attr_accessor :visually_similar_products

      # @return [RecognizedEntitiesModule] A list of groups that contain images
      # of entities that match the entity found in the specified image. For
      # example, the response might include images from the general celebrity
      # group if the entity was recognized in that group.
      attr_accessor :recognized_entity_groups

      # @return [ImageTagsModule] A list of characteristics of the content
      # found in the image. For example, if the image is of a person, the tags
      # might indicate the person's gender and the type of clothes they're
      # wearing.
      attr_accessor :image_tags


      #
      # Mapper for ImageInsights class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ImageInsights',
          type: {
            name: 'Composite',
            class_name: 'ImageInsights',
            model_properties: {
              _type: {
                client_side_validation: true,
                required: true,
                serialized_name: '_type',
                type: {
                  name: 'String'
                }
              },
              id: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              },
              read_link: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'readLink',
                type: {
                  name: 'String'
                }
              },
              web_search_url: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'webSearchUrl',
                type: {
                  name: 'String'
                }
              },
              image_insights_token: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'imageInsightsToken',
                type: {
                  name: 'String'
                }
              },
              best_representative_query: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'bestRepresentativeQuery',
                type: {
                  name: 'Composite',
                  class_name: 'Query'
                }
              },
              image_caption: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'imageCaption',
                type: {
                  name: 'Composite',
                  class_name: 'ImageInsightsImageCaption'
                }
              },
              related_collections: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'relatedCollections',
                type: {
                  name: 'Composite',
                  class_name: 'RelatedCollectionsModule'
                }
              },
              pages_including: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'pagesIncluding',
                type: {
                  name: 'Composite',
                  class_name: 'ImagesModule'
                }
              },
              shopping_sources: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'shoppingSources',
                type: {
                  name: 'Composite',
                  class_name: 'AggregateOffer'
                }
              },
              related_searches: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'relatedSearches',
                type: {
                  name: 'Composite',
                  class_name: 'RelatedSearchesModule'
                }
              },
              recipes: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'recipes',
                type: {
                  name: 'Composite',
                  class_name: 'RecipesModule'
                }
              },
              visually_similar_images: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'visuallySimilarImages',
                type: {
                  name: 'Composite',
                  class_name: 'ImagesModule'
                }
              },
              visually_similar_products: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'visuallySimilarProducts',
                type: {
                  name: 'Composite',
                  class_name: 'ImagesModule'
                }
              },
              recognized_entity_groups: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'recognizedEntityGroups',
                type: {
                  name: 'Composite',
                  class_name: 'RecognizedEntitiesModule'
                }
              },
              image_tags: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'imageTags',
                type: {
                  name: 'Composite',
                  class_name: 'ImageTagsModule'
                }
              }
            }
          }
        }
      end
    end
  end
end
